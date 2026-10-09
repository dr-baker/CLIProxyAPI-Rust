//! Responses API over websocket (`GET /v1/responses`), the transport Codex uses.
//!
//! Each `response.create` message is one turn. Codex OAuth accounts get a
//! native upstream websocket (server-side `previous_response_id` works as-is);
//! every other provider is served through the normal pipeline, with
//! `previous_response_id` expanded from a small local history.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::http::HeaderMap;
use futures::{FutureExt, SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite;

use crate::accounts::{Account, Only, Pick, Provider};
use crate::config::Config;
use crate::formats::{StreamParser, responses};
use crate::ir::{self, Event, Format, Usage};
use crate::proxy::{self, Call, Reply, Tracker};
use crate::sse::SseEvent;
use crate::state::App;

type Upstream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type ClientTx = futures::stream::SplitSink<WebSocket, Message>;
type ClientRx = futures::stream::SplitStream<WebSocket>;

struct Client {
    tx: ClientTx,
    rx: ClientRx,
    // Keep one follow-up create in order while continuing to receive controls.
    pending: Option<ClientCreate>,
}

struct ClientCreate {
    request_id: u64,
    body: Value,
}

enum ClientFrame {
    Create(ClientCreate),
    Interrupt { request_id: u64, body: Value },
    Invalid { request_id: u64, message: String },
    Ignore,
    Closed,
}

fn client_frame(app: &App, message: Option<Result<Message, axum::Error>>) -> ClientFrame {
    let text = match message {
        Some(Ok(Message::Text(text))) => text.to_string(),
        Some(Ok(Message::Binary(bytes))) => String::from_utf8_lossy(&bytes).into_owned(),
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return ClientFrame::Closed,
        _ => return ClientFrame::Ignore,
    };
    let request_id = app.stats.next_id();
    let parsed = serde_json::from_str::<Value>(&text);
    audit(
        app,
        request_id,
        "downstream_request",
        parsed.as_ref().map(Value::clone).unwrap_or_else(|_| Value::String(text)),
    );
    let Ok(mut body) = parsed else {
        return ClientFrame::Invalid { request_id, message: "invalid JSON".into() };
    };
    match body["type"].as_str() {
        Some("response.create") => {
            body.as_object_mut().unwrap().remove("type");
            ClientFrame::Create(ClientCreate { request_id, body })
        }
        Some("response.interrupt") => {
            if body["response_id"].as_str().is_none_or(|id| id.trim().is_empty()) {
                return ClientFrame::Invalid {
                    request_id,
                    message: "response.interrupt requires a response_id".into(),
                };
            }
            if body["mode"] != "discard_partial_items" {
                return ClientFrame::Invalid {
                    request_id,
                    message: "response.interrupt requires mode discard_partial_items".into(),
                };
            }
            ClientFrame::Interrupt { request_id, body }
        }
        _ => ClientFrame::Invalid {
            request_id,
            message: format!("unsupported message type `{}`", body["type"].as_str().unwrap_or_default()),
        },
    }
}

enum ActiveInput {
    Interrupt { request_id: u64, body: Value },
    Invalid { request_id: u64, message: String },
    Continue,
    Closed,
}

fn active_input(client: &mut Client, sess: &Session, response_id: Option<&str>, frame: ClientFrame) -> ActiveInput {
    match frame {
        ClientFrame::Create(create) => {
            if client.pending.is_some() {
                ActiveInput::Invalid {
                    request_id: create.request_id,
                    message: "a follow-up response.create is already queued".into(),
                }
            } else {
                client.pending = Some(create);
                ActiveInput::Continue
            }
        }
        ClientFrame::Interrupt { request_id, body } => {
            let id = body["response_id"].as_str().unwrap();
            if response_id == Some(id) {
                ActiveInput::Interrupt { request_id, body }
            } else if sess.contains(id) {
                // Completion and interrupt can race; a completed response needs no control.
                ActiveInput::Continue
            } else {
                ActiveInput::Invalid {
                    request_id,
                    message: "response_id does not match a response on this websocket".into(),
                }
            }
        }
        ClientFrame::Invalid { request_id, message } => ActiveInput::Invalid { request_id, message },
        ClientFrame::Ignore => ActiveInput::Continue,
        ClientFrame::Closed => ActiveInput::Closed,
    }
}

fn idle_input(sess: &Session, frame: ClientFrame) -> ClientFrame {
    match frame {
        ClientFrame::Interrupt { request_id, body } => {
            if sess.contains(body["response_id"].as_str().unwrap()) {
                ClientFrame::Ignore
            } else {
                ClientFrame::Invalid {
                    request_id,
                    message: "response_id does not match a response on this websocket".into(),
                }
            }
        }
        other => other,
    }
}

async fn invalid_frame(app: &App, client: &mut Client, request_id: u64, message: &str) -> Result<(), ClientGone> {
    send(
        app,
        request_id,
        &mut client.tx,
        error_event(400, &json!({"error":{"message":message,"type":"invalid_request_error"}})),
    )
    .await
}

const UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IDLE_DRAIN: usize = 32;

struct UpstreamFailure {
    operation: &'static str,
    status: u16,
    message: String,
}

impl UpstreamFailure {
    fn timeout(operation: &'static str) -> Self {
        Self { operation, status: 504, message: format!("codex websocket {operation} timed out") }
    }

    fn socket(operation: &'static str, error: &tungstenite::Error) -> Self {
        Self { operation, status: 502, message: format!("codex websocket {operation} failed: {}", socket_error(error)) }
    }

    fn log(&self, connection_id: &str, phase: &'static str) {
        tracing::warn!(connection_id, phase, operation = self.operation, status = self.status, error = %self.message,
            "codex upstream websocket failure");
    }
}

// Some errors contain raw frames, HTTP bodies, or URLs. Keep transport diagnostics safe.
fn socket_error(error: &tungstenite::Error) -> String {
    match error {
        tungstenite::Error::Io(error) => format!("I/O {:?}, OS error {:?}", error.kind(), error.raw_os_error()),
        tungstenite::Error::Protocol(error) => format!("protocol error: {error}"),
        tungstenite::Error::Http(response) => format!("handshake rejected: {}", response.status()),
        tungstenite::Error::ConnectionClosed => "connection closed".into(),
        tungstenite::Error::AlreadyClosed => "connection already closed".into(),
        tungstenite::Error::Tls(_) => "TLS error".into(),
        tungstenite::Error::Capacity(_) => "capacity exceeded".into(),
        tungstenite::Error::WriteBufferFull(_) => "write buffer full".into(),
        tungstenite::Error::Utf8(_) => "invalid UTF-8".into(),
        tungstenite::Error::AttackAttempt => "attack attempt detected".into(),
        tungstenite::Error::Url(_) => "invalid websocket URL".into(),
        tungstenite::Error::HttpFormat(_) => "invalid HTTP format".into(),
    }
}

async fn upstream_write(
    operation: &'static str,
    write: impl Future<Output = Result<(), tungstenite::Error>>,
) -> Result<(), UpstreamFailure> {
    tokio::time::timeout(UPSTREAM_WRITE_TIMEOUT, write)
        .await
        .map_err(|_| UpstreamFailure::timeout(operation))?
        .map_err(|error| UpstreamFailure::socket(operation, &error))
}

async fn close_upstream(up: &mut Upstream, connection_id: &str, phase: &'static str) {
    if let Err(failure) = upstream_write("close", up.close(None)).await {
        failure.log(connection_id, phase);
    }
}

const HISTORY: usize = 4;

#[derive(Default)]
struct Session {
    /// response id -> full conversation input including that response's output.
    history: VecDeque<(String, Vec<Value>)>,
    upstream: Option<(Arc<Account>, Upstream)>,
    /// IDs created on the current upstream connection, excluding HTTP turns.
    upstream_ids: VecDeque<String>,
    pinned: Option<String>,
    connection_id: String,
}

impl Session {
    fn contains(&self, id: &str) -> bool {
        self.history.iter().any(|(known, _)| known == id)
    }

    fn discard_upstream(&mut self) -> Option<(Arc<Account>, Upstream)> {
        self.upstream_ids.clear();
        self.upstream.take()
    }

    async fn close_upstream(&mut self, phase: &'static str) {
        if let Some((_, mut up)) = self.discard_upstream() {
            close_upstream(&mut up, &self.connection_id, phase).await;
        }
    }

    fn lookup(&self, id: &str) -> Option<Vec<Value>> {
        self.history.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
    }

    fn remember(&mut self, id: String, items: Vec<Value>) {
        self.history.push_back((id, items));
        while self.history.len() > HISTORY {
            self.history.pop_front();
        }
    }

    fn remember_upstream(&mut self, id: String) {
        self.upstream_ids.push_back(id);
        while self.upstream_ids.len() > HISTORY {
            self.upstream_ids.pop_front();
        }
    }
}

#[derive(Default)]
struct TurnOutput {
    /// Complete raw items, including opaque reasoning fields needed for replay.
    items: BTreeMap<u64, Value>,
}

impl TurnOutput {
    fn observe(&mut self, event: &Value, event_name: Option<&str>) {
        let kind = event["type"].as_str().or(event_name);
        if kind == Some("response.output_item.done")
            && let Some(index) = event["output_index"].as_u64()
            && event["item"].is_object()
        {
            self.items.insert(index, event["item"].clone());
        }
    }

    fn captured_items(&self, response: &Value) -> Vec<Value> {
        let interrupted = response["incomplete_details"]["reason"] == "interrupted";
        let items = if let Some(output) = response["output"].as_array().filter(|output| !output.is_empty()) {
            output.clone()
        } else {
            // Codex can put completed items in item.done events and leave final
            // output empty, including interrupted turns. Preserve complete raw
            // items for replay while filtering partial items below.
            self.items.values().cloned().collect()
        };
        items
            .into_iter()
            .filter(|item| {
                !interrupted
                    || !matches!(item["status"].as_str(), Some("in_progress" | "incomplete" | "cancelled" | "canceled"))
            })
            .collect()
    }
}

async fn idle_upstream(app: &App, sess: &mut Session, event: Option<Result<tungstenite::Message, tungstenite::Error>>) {
    let kind = match &event {
        Some(Ok(tungstenite::Message::Ping(_))) => "ping",
        Some(Ok(tungstenite::Message::Close(_))) => "close",
        Some(Err(_)) => "read_error",
        None => "eof",
        _ => "other",
    };
    if kind != "other" {
        let close_code = match &event {
            Some(Ok(tungstenite::Message::Close(Some(frame)))) => Some(u16::from(frame.code)),
            _ => None,
        };
        audit(
            app,
            0,
            "upstream_idle_control",
            json!({"connection_id":sess.connection_id, "kind":kind, "close_code":close_code}),
        );
    }
    match event {
        Some(Ok(tungstenite::Message::Ping(_))) => {
            // Tungstenite queues its automatic Pong until the next write/flush.
            let (_, up) = sess.upstream.as_mut().unwrap();
            if let Err(failure) = upstream_write("flush", up.flush()).await {
                failure.log(&sess.connection_id, "idle");
                sess.discard_upstream();
            }
        }
        Some(Ok(tungstenite::Message::Close(frame))) => {
            tracing::debug!(
                connection_id = sess.connection_id,
                phase = "idle",
                close_code = frame.as_ref().map(|frame| u16::from(frame.code)),
                "codex upstream websocket closed"
            );
            if let Some((_, mut up)) = sess.discard_upstream()
                && let Err(failure) = upstream_write("flush", up.flush()).await
            {
                failure.log(&sess.connection_id, "idle_close");
            }
        }
        Some(Err(error)) => {
            UpstreamFailure::socket("read", &error).log(&sess.connection_id, "idle");
            sess.discard_upstream();
        }
        None => {
            tracing::debug!(connection_id = sess.connection_id, phase = "idle", "codex upstream websocket ended");
            sess.discard_upstream();
        }
        Some(Ok(tungstenite::Message::Text(text))) => idle_data(app, sess, &text),
        Some(Ok(tungstenite::Message::Binary(data))) => idle_data(app, sess, &String::from_utf8_lossy(&data)),
        Some(Ok(_)) => {}
    }
}

fn idle_data(app: &App, sess: &mut Session, data: &str) {
    if let Ok(value) = serde_json::from_str::<Value>(data)
        && value["type"] == "codex.rate_limits"
    {
        audit(app, 0, "upstream_idle_quota", json!({"connection_id":sess.connection_id, "event":value}));
        if let Some((acct, _)) = &sess.upstream {
            crate::quota::observe_codex_event(acct, &value);
        }
    } else {
        tracing::warn!(
            connection_id = sess.connection_id,
            phase = "idle",
            "unexpected codex upstream application frame between turns"
        );
        sess.discard_upstream();
    }
}

async fn drain_idle_upstream(app: &App, sess: &mut Session) {
    for _ in 0..MAX_IDLE_DRAIN {
        let Some((_, up)) = &mut sess.upstream else { return };
        let Some(event) = tokio::task::unconstrained(up.next()).now_or_never() else { return };
        idle_upstream(app, sess, event).await;
    }
    // A busy upstream must not prevent a ready client from submitting or closing.
    tracing::warn!(
        connection_id = sess.connection_id,
        phase = "idle",
        "codex upstream idle drain limit reached; reconnecting on the next turn"
    );
    sess.discard_upstream();
}

// Subscription admission may wait on HTTP. Keep the retained socket alive and
// process queued Close frames before deciding whether it can serve this turn.
async fn while_idle<T>(app: &App, sess: &mut Session, wait: impl Future<Output = T>) -> T {
    tokio::pin!(wait);
    loop {
        tokio::select! {
            biased;
            result = &mut wait => {
                drain_idle_upstream(app, sess).await;
                return result;
            }
            event = async {
                match &mut sess.upstream {
                    Some((_, up)) => up.next().await,
                    None => std::future::pending().await,
                }
            } => idle_upstream(app, sess, event).await,
        }
    }
}

struct ClientGone;

fn audit(app: &App, request_id: u64, direction: &str, data: Value) {
    if let Err(e) = app.audit.record(request_id, direction, "websocket", data) {
        tracing::error!("websocket audit write failed: {e}");
    }
}

async fn send(app: &App, request_id: u64, tx: &mut ClientTx, text: String) -> Result<(), ClientGone> {
    let data = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text.clone()));
    audit(app, request_id, "downstream_event", data);
    tx.send(Message::Text(text.into())).await.map_err(|_| ClientGone)
}

fn error_event(status: u16, body: &Value) -> String {
    let err = if body["error"].is_object() {
        body["error"].clone()
    } else {
        json!({ "message": proxy::error_message(&body.to_string()) })
    };
    json!({ "type": "error", "status": status, "error": err }).to_string()
}

fn input_items(body: &Value) -> Vec<Value> {
    match &body["input"] {
        Value::String(s) => {
            vec![json!({ "type": "message", "role": "user", "content": [{ "type": "input_text", "text": s }] })]
        }
        Value::Array(a) => a.clone(),
        _ => vec![],
    }
}

fn is_warmup(body: &Value) -> bool {
    body["generate"].as_bool() == Some(false)
}

fn previous_missing() -> Value {
    json!({ "error": {
        "message": "Previous response is not available on this websocket; resend the full conversation input without previous_response_id",
        "type": "invalid_request_error", "code": "previous_response_not_found", "param": "previous_response_id"
    }})
}

fn normalize_completion(event: &mut Value) -> bool {
    if event["type"] == "response.done" {
        event["type"] = "response.completed".into();
        true
    } else {
        false
    }
}

pub async fn handle(app: Arc<App>, headers: HeaderMap, socket: WebSocket) {
    let (tx, rx) = socket.split();
    let mut client = Client { tx, rx, pending: None };
    let mut sess = Session { connection_id: uuid::Uuid::new_v4().to_string(), ..Default::default() };
    loop {
        let frame = if let Some(create) = client.pending.take() {
            ClientFrame::Create(create)
        } else {
            tokio::select! {
                biased;
                message = client.rx.next() => client_frame(&app, message),
                upstream = async {
                    match &mut sess.upstream {
                        Some((_, up)) => up.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    idle_upstream(&app, &mut sess, upstream).await;
                    continue;
                }
            }
        };
        match idle_input(&sess, frame) {
            ClientFrame::Create(create) => {
                drain_idle_upstream(&app, &mut sess).await;
                if turn(&app, create.request_id, &headers, &mut sess, create.body, &mut client).await.is_err() {
                    break;
                }
            }
            ClientFrame::Interrupt { .. } => unreachable!("idle_input handles interrupts"),
            ClientFrame::Invalid { request_id, message } => {
                if invalid_frame(&app, &mut client, request_id, &message).await.is_err() {
                    break;
                }
            }
            ClientFrame::Ignore => {}
            ClientFrame::Closed => break,
        }
    }
    sess.close_upstream("client_closed").await;
}

async fn turn(
    app: &Arc<App>,
    request_id: u64,
    headers: &HeaderMap,
    sess: &mut Session,
    mut body: Value,
    client: &mut Client,
) -> Result<(), ClientGone> {
    // Full conversation for local history (and for providers without server state).
    let prev = body["previous_response_id"].as_str().map(String::from);
    let mut full = prev.as_deref().and_then(|id| sess.lookup(id)).unwrap_or_default();
    full.extend(input_items(&body));

    let cfg = app.cfg();
    if cfg.codex_websockets {
        match native_turn(app, request_id, headers, sess, &body, &full, client).await {
            Native::Done => return Ok(()),
            Native::Gone => return Err(ClientGone),
            Native::Fallback => {}
            Native::Error(status, error) => {
                return send(app, request_id, &mut client.tx, error_event(status, &error)).await;
            }
        }
    } else if let Native::Error(status, error) = unavailable(&cfg, &body, "codex-websockets is disabled") {
        let mut tracker = Tracker::new_with_id(
            app,
            Format::Responses,
            true,
            "upstream_ws",
            body["model"].as_str().unwrap_or_default(),
            request_id,
        );
        tracker.finish(status, &Usage::default(), Some(proxy::error_message(&error.to_string())));
        return send(app, request_id, &mut client.tx, error_event(status, &error)).await;
    }

    if let Some(id) = &prev {
        if sess.lookup(id).is_none() {
            return send(app, request_id, &mut client.tx, error_event(400, &previous_missing())).await;
        }
        body["input"] = Value::Array(full.clone());
        body.as_object_mut().unwrap().remove("previous_response_id");
    }

    let call = Call {
        format: Format::Responses,
        body,
        headers: headers.clone(),
        stream: true,
        transport: "ws_http",
        path_model: None,
        pinned: sess.pinned.clone(),
        request_id: Some(request_id),
    };
    match proxy::execute(app.clone(), call).await {
        Reply::Stream { frames, .. } => relay_http_response(app, request_id, sess, &full, client, frames).await,
        Reply::Json(v) => {
            let _ = capture(sess, &json!({ "response": v }), &full, &TurnOutput::default());
            send(app, request_id, &mut client.tx, json!({ "type": "response.completed", "response": v }).to_string())
                .await
        }
        Reply::Error(status, body) => send(app, request_id, &mut client.tx, error_event(status, &body)).await,
    }
}

async fn relay_http_response(
    app: &Arc<App>,
    request_id: u64,
    sess: &mut Session,
    full: &[Value],
    client: &mut Client,
    mut frames: proxy::FrameStream,
) -> Result<(), ClientGone> {
    let mut output = TurnOutput::default();
    let mut response_id = None;
    loop {
        let next = tokio::select! {
            next = frames.next() => next,
            message = client.rx.next() => {
                let frame = client_frame(app, message);
                match active_input(client, sess, response_id.as_deref(), frame) {
                    ActiveInput::Interrupt { request_id: control_id, .. } => {
                        // An HTTP body has no channel for native response controls.
                        // Drop the stream and report that limitation without fabricating
                        // a completed response, token usage, or another generation.
                        return send(app, control_id, &mut client.tx, error_event(400, &json!({"error":{
                            "message":"response.interrupt requires an upstream websocket; the HTTP response stream was closed",
                            "type":"invalid_request_error", "code":"response_interrupt_unsupported"
                        }}))).await;
                    }
                    ActiveInput::Invalid { request_id, message } => invalid_frame(app, client, request_id, &message).await?,
                    ActiveInput::Closed => return Err(ClientGone),
                    ActiveInput::Continue => {}
                }
                continue;
            }
        };
        let Some(mut frame) = next else { return Ok(()) };
        let mut event = serde_json::from_str::<Value>(&frame.data).unwrap_or(Value::Null);
        output.observe(&event, frame.event.as_deref());
        if normalize_completion(&mut event) {
            frame.data = event.to_string();
        }
        if event["type"] == "response.created" || frame.event.as_deref() == Some("response.created") {
            response_id = event["response"]["id"].as_str().map(String::from);
        }
        if matches!(event["type"].as_str(), Some("response.completed" | "response.incomplete"))
            || matches!(frame.event.as_deref(), Some("response.completed" | "response.incomplete"))
        {
            let _ = capture(sess, &event, full, &output);
            response_id = None;
        }
        send(app, request_id, &mut client.tx, frame.data).await?;
    }
}

fn capture(sess: &mut Session, v: &Value, full: &[Value], output: &TurnOutput) -> Option<String> {
    let r = &v["response"];
    let id = r["id"].as_str()?.to_string();
    let mut items = full.to_vec();
    items.extend(output.captured_items(r));
    sess.remember(id.clone(), items);
    Some(id)
}

enum Native {
    Done,
    Gone,
    Fallback,
    Error(u16, Value),
}

fn unavailable(cfg: &Config, body: &Value, reason: &str) -> Native {
    if cfg.codex_subscription_only || is_warmup(body) {
        Native::Error(
            502,
            json!({ "error": {
                "message": format!("Codex upstream websocket unavailable: {reason}"),
                "type": "upstream_error", "code": "upstream_websocket_unavailable"
            }}),
        )
    } else {
        Native::Fallback
    }
}

fn tracked_unavailable(tracker: &mut Tracker, cfg: &Config, body: &Value, reason: &str) -> Native {
    let result = unavailable(cfg, body, reason);
    match &result {
        Native::Error(status, error) => {
            tracker.finish(*status, &Usage::default(), Some(proxy::error_message(&error.to_string())));
        }
        _ => tracker.cancel(),
    }
    result
}

fn current_account_can_reuse(
    current: Option<&Arc<Account>>,
    saved: &Arc<Account>,
    model: &str,
    only: Option<&Only>,
    force_prefix: bool,
) -> bool {
    let Some(current) = current else { return false };
    let allowed = match only {
        Some(Only::Provider(provider)) => *provider == current.provider,
        Some(Only::Prefix(prefix)) => current.prefix.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(prefix)),
        None => !(force_prefix && current.prefix.is_some()),
    };
    Arc::ptr_eq(current, saved)
        && allowed
        && current.provider == Provider::Codex
        && current.is_oauth()
        && current.proxy_url.is_none()
        && current.resolve(model).is_some()
        && current.cooling_until(model).is_none()
        && !current.state.lock().disabled
}

fn prepare_native_body(
    sess: &Session,
    body: &Value,
    full: &[Value],
    model: &str,
    new_connection: bool,
    suffix: Option<&ir::Reasoning>,
) -> Result<Value, Value> {
    let mut payload = body.clone();
    if let Some(id) = body["previous_response_id"].as_str()
        && (new_connection || !sess.upstream_ids.iter().any(|known| known == id))
    {
        if sess.lookup(id).is_none() {
            return Err(previous_missing());
        }
        // store=false state belongs to one upstream connection. A new socket,
        // or an ID returned by HTTP fallback, needs the complete local input.
        payload["input"] = Value::Array(full.to_vec());
        payload.as_object_mut().unwrap().remove("previous_response_id");
    }
    crate::upstream::sanitize_codex_body(&mut payload, model, true);
    payload.as_object_mut().unwrap().remove("stream");
    if let Some(effort) = suffix.and_then(ir::Reasoning::effort_level) {
        payload["reasoning"]["effort"] = effort.into();
    }
    payload["type"] = "response.create".into();
    Ok(payload)
}

async fn connect(
    app: &App,
    request_id: u64,
    acct: &Arc<Account>,
    client_headers: &HeaderMap,
) -> Result<Upstream, String> {
    let (url, headers) = crate::upstream::codex_ws_url(acct, client_headers);
    let mut req =
        tungstenite::client::IntoClientRequest::into_client_request(url.as_str()).map_err(|e| e.to_string())?;
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) =
            (tungstenite::http::HeaderName::from_bytes(k.as_bytes()), tungstenite::http::HeaderValue::from_str(&v))
        {
            req.headers_mut().insert(name, val);
        }
    }
    let (ws, response) =
        tokio::time::timeout(std::time::Duration::from_secs(20), tokio_tungstenite::connect_async(req))
            .await
            .map_err(|_| "websocket handshake timed out".to_string())?
            .map_err(|e| match e {
                tungstenite::Error::Http(resp) => {
                    crate::quota::observe(acct, resp.headers());
                    audit(app, request_id, "upstream_handshake", json!({ "status": resp.status().as_u16() }));
                    format!("websocket handshake rejected: {}", resp.status())
                }
                other => other.to_string(),
            })?;
    crate::quota::observe(acct, response.headers());
    audit(app, request_id, "upstream_handshake", json!({ "status": response.status().as_u16() }));
    Ok(ws)
}

async fn native_turn(
    app: &Arc<App>,
    request_id: u64,
    headers: &HeaderMap,
    sess: &mut Session,
    body: &Value,
    full: &[Value],
    client: &mut Client,
) -> Native {
    let cfg = app.cfg();
    let (model, suffix) = ir::split_model_suffix(body["model"].as_str().unwrap_or_default());
    let (only, model) = app.pool.route(&model);
    let model = app.pool.canonical(&model, only.as_ref());
    let mut tracker = Tracker::new_with_id(app, Format::Responses, true, "upstream_ws", &model, request_id);
    if model.is_empty() {
        tracker.finish(400, &Usage::default(), Some("`model` is required".into()));
        return Native::Error(
            400,
            json!({ "error": { "message": "`model` is required", "type": "invalid_request_error" } }),
        );
    }
    // Native websockets don't go through HTTP proxies.
    if !cfg.proxy_url.is_empty() {
        return tracked_unavailable(
            &mut tracker,
            &cfg,
            body,
            "proxy-url must be empty for native websocket connections",
        );
    }
    if matches!(only.as_ref(), Some(Only::Provider(provider)) if *provider != Provider::Codex) {
        return tracked_unavailable(&mut tracker, &cfg, body, "the requested provider is not Codex");
    }

    // Reuse the session's upstream socket when it can serve this model.
    let reuse = sess.upstream.as_ref().is_some_and(|(a, _)| {
        let current = app.pool.get(&a.id);
        current_account_can_reuse(current.as_ref(), a, &model, only.as_ref(), cfg.force_model_prefix)
    });
    if !reuse {
        sess.close_upstream("account_changed").await;
        let (acct, _) = match app.pool.pick(&model, &[], cfg.routing, sess.pinned.as_deref(), only.as_ref()) {
            Pick::Ok(a, m) => (a, m),
            Pick::Cooling(until) => {
                let message = format!("all Codex accounts for {model} are rate limited until {until}");
                tracker.finish(429, &Usage::default(), Some(message.clone()));
                return Native::Error(
                    429,
                    json!({ "error": { "message": message, "type": "rate_limit_error", "code": "rate_limit_exceeded" } }),
                );
            }
            Pick::None => {
                return tracked_unavailable(&mut tracker, &cfg, body, "no eligible Codex OAuth account is available");
            }
        };
        tracker.attempt(&acct);
        if acct.provider != Provider::Codex || !acct.is_oauth() || acct.proxy_url.is_some() {
            return tracked_unavailable(
                &mut tracker,
                &cfg,
                body,
                "the selected account is not a direct Codex OAuth account",
            );
        }
        if let Err(e) = crate::oauth::ensure_fresh(app, &acct, chrono::Duration::minutes(5), false).await {
            return tracked_unavailable(&mut tracker, &cfg, body, &format!("token refresh failed: {e}"));
        }
        match connect(app, tracker.id(), &acct, headers).await {
            Ok(ws) => {
                sess.pinned = Some(acct.id.clone());
                sess.upstream = Some((acct, ws));
            }
            Err(e) => {
                tracing::warn!(account = %acct.label, "codex websocket unavailable: {e}");
                return tracked_unavailable(&mut tracker, &cfg, body, &e);
            }
        }
    }
    let acct = sess.upstream.as_ref().unwrap().0.clone();
    let upstream_model = acct.resolve(&model).unwrap_or(model.clone());
    if reuse {
        tracker.attempt(&acct);
    }
    let mut fresh_connection = !reuse;
    // One reconnect is safe here: no response.create has been sent yet. A new
    // handshake gets another allowance check before any inference payload.
    for admission in 0..2 {
        let allowance = while_idle(app, sess, crate::quota::require_subscription(app, &acct, &upstream_model)).await;
        if let Err(error) = allowance {
            let message = error.to_string();
            sess.close_upstream("subscription_rejected").await;
            tracker.finish(403, &Usage::default(), Some(message.clone()));
            return Native::Error(
                403,
                json!({"error":{"message":message, "type":"permission_error", "code":"subscription_required"}}),
            );
        }
        if sess.upstream.is_some() {
            break;
        }
        if admission == 1 {
            return tracked_unavailable(&mut tracker, &cfg, body, "websocket closed during subscription admission");
        }
        tracker.attempt(&acct);
        match connect(app, tracker.id(), &acct, headers).await {
            Ok(up) => {
                sess.upstream = Some((acct.clone(), up));
                fresh_connection = true;
            }
            Err(error) => return tracked_unavailable(&mut tracker, &cfg, body, &error),
        }
    }
    let (acct, mut up) = sess.upstream.take().unwrap();
    let payload = match prepare_native_body(sess, body, full, &upstream_model, fresh_connection, suffix.as_ref()) {
        Ok(payload) => payload,
        Err(error) => {
            sess.upstream = Some((acct, up));
            tracker.finish(400, &Usage::default(), Some(proxy::error_message(&error.to_string())));
            return Native::Error(400, error);
        }
    };
    audit(app, tracker.id(), "upstream_request", payload.clone());
    if let Err(failure) = upstream_write("send", up.send(tungstenite::Message::Text(payload.to_string().into()))).await
    {
        failure.log(&sess.connection_id, "turn");
        sess.upstream_ids.clear();
        tracker.finish(failure.status, &Usage::default(), Some(failure.message.clone()));
        // A failed write may already have submitted the request. Let the client recover.
        return Native::Error(failure.status, json!({"error":{"message":failure.message, "type":"upstream_error"}}));
    }

    relay_native_response(app, sess, body, full, client, NativeResponse { acct, up, tracker, model }).await
}

struct NativeResponse {
    acct: Arc<Account>,
    up: Upstream,
    tracker: Tracker,
    model: String,
}

async fn relay_native_response(
    app: &Arc<App>,
    sess: &mut Session,
    body: &Value,
    full: &[Value],
    client: &mut Client,
    response: NativeResponse,
) -> Native {
    let cfg = app.cfg();
    let NativeResponse { acct, mut up, mut tracker, model } = response;
    let mut parser = responses::Parser::default();
    let mut output = TurnOutput::default();
    let mut usage = Usage::default();
    let mut evs = Vec::new();
    let mut error: Option<(u16, String)> = None;
    let mut forwarded = false;
    let mut terminal = false;
    let mut response_id = None;
    let mut interrupt_sent = false;
    let mut interrupted_terminal = false;
    let mut read_deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let next = tokio::select! {
            next = tokio::time::timeout_at(read_deadline, up.next()) => next,
            message = client.rx.next() => {
                let frame = client_frame(app, message);
                match active_input(client, sess, response_id.as_deref(), frame) {
                    ActiveInput::Interrupt { request_id, body } => {
                        if !interrupt_sent {
                            audit(app, request_id, "upstream_control", body.clone());
                            if let Err(failure) = upstream_write("interrupt", up.send(tungstenite::Message::Text(body.to_string().into()))).await {
                                failure.log(&sess.connection_id, "turn_interrupt");
                                error = Some((failure.status, failure.message));
                                break;
                            }
                            interrupt_sent = true;
                        }
                    }
                    ActiveInput::Invalid { request_id, message } => {
                        if invalid_frame(app, client, request_id, &message).await.is_err() {
                            tracker.downstream_write_failed(&usage);
                            return Native::Gone;
                        }
                    }
                    ActiveInput::Closed => {
                        sess.upstream_ids.clear();
                        tracker.finish(499, &usage, Some("client websocket closed during response".into()));
                        return Native::Gone;
                    }
                    ActiveInput::Continue => {}
                }
                // Client chatter must not extend the upstream read deadline.
                continue;
            }
        };
        read_deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        let mut text = match next {
            Ok(Some(Ok(tungstenite::Message::Text(t)))) => t.to_string(),
            Ok(Some(Ok(tungstenite::Message::Binary(b)))) => String::from_utf8_lossy(&b).into_owned(),
            Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                tracing::warn!(
                    connection_id = sess.connection_id,
                    phase = "turn",
                    close_code = frame.as_ref().map(|frame| u16::from(frame.code)),
                    "codex upstream websocket closed during turn"
                );
                if let Err(failure) = upstream_write("flush", up.flush()).await {
                    failure.log(&sess.connection_id, "turn_close");
                }
                error = Some((502, "codex websocket closed".into()));
                break;
            }
            Ok(None) => {
                tracing::warn!(
                    connection_id = sess.connection_id,
                    phase = "turn",
                    "codex upstream websocket ended during turn"
                );
                error = Some((502, "codex websocket closed".into()));
                break;
            }
            Ok(Some(Ok(tungstenite::Message::Ping(_)))) => {
                if let Err(failure) = upstream_write("flush", up.flush()).await {
                    failure.log(&sess.connection_id, "turn");
                    error = Some((failure.status, failure.message));
                    break;
                }
                continue;
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => {
                let failure = UpstreamFailure::socket("read", &e);
                failure.log(&sess.connection_id, "turn");
                error = Some((failure.status, failure.message));
                break;
            }
            Err(_) => {
                let failure = UpstreamFailure::timeout("read");
                failure.log(&sess.connection_id, "turn");
                error = Some((failure.status, failure.message));
                break;
            }
        };
        let mut v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let data = if v.is_null() { Value::String(text.clone()) } else { v.clone() };
        audit(app, tracker.id(), "upstream_event", data);
        output.observe(&v, None);
        if normalize_completion(&mut v) {
            text = v.to_string();
        }
        let kind = v["type"].as_str().unwrap_or_default().to_string();
        if kind == "response.created" {
            response_id = v["response"]["id"].as_str().map(String::from);
        }
        crate::quota::observe_codex_event(&acct, &v);
        parser.feed(&SseEvent { event: None, data: text.clone() }, &mut evs);
        for ev in evs.drain(..) {
            match ev {
                Event::Usage(u) => usage.merge(&u),
                Event::Error { status, message } => error = Some((status, message)),
                Event::Text(_) | Event::Reasoning(_) | Event::ToolStart { .. } => tracker.first_token(),
                _ => {}
            }
        }
        // Rate limits / auth failures before any output can be retried elsewhere.
        if !forwarded
            && matches!(kind.as_str(), "error" | "response.failed")
            && let Some((status @ (429 | 401 | 403), msg)) = error.clone()
        {
            if status == 429 {
                acct.cool(Some(&model), chrono::Utc::now() + chrono::Duration::seconds(60), &format!("429: {msg}"));
            } else {
                acct.cool(None, chrono::Utc::now() + chrono::Duration::minutes(10), &format!("{status}: {msg}"));
            }
            close_upstream(&mut up, &sess.connection_id, "quota_or_auth_rejected").await;
            sess.pinned = None;
            sess.upstream_ids.clear();
            if !cfg.codex_subscription_only && !is_warmup(body) {
                tracker.cancel();
                return Native::Fallback;
            }
            tracker.finish(status, &usage, Some(msg));
            return if send(app, tracker.id(), &mut client.tx, text).await.is_err() {
                Native::Gone
            } else {
                Native::Done
            };
        }
        if (kind == "response.completed" || kind == "response.incomplete")
            && let Some(id) = capture(sess, &v, full, &output)
        {
            sess.remember_upstream(id);
        }
        terminal = matches!(kind.as_str(), "response.completed" | "response.incomplete" | "response.failed" | "error");
        interrupted_terminal =
            kind == "response.incomplete" && v["response"]["incomplete_details"]["reason"] == "interrupted";
        forwarded = true;
        if send(app, tracker.id(), &mut client.tx, text).await.is_err() {
            tracker.downstream_write_failed(&usage);
            return Native::Gone;
        }
        if terminal {
            break;
        }
    }
    if terminal {
        sess.upstream = Some((acct.clone(), up));
    } else {
        // The upstream socket died mid-turn: tell the client and reconnect next turn.
        sess.upstream_ids.clear();
        let (status, msg) = error.clone().unwrap_or((502, "codex websocket closed".into()));
        let body = json!({ "error": { "message": msg, "type": "upstream_error" } });
        if send(app, tracker.id(), &mut client.tx, error_event(status, &body)).await.is_err() {
            tracker.finish(status, &usage, Some(msg));
            return Native::Gone;
        }
    }
    match error {
        Some((s, m)) => tracker.finish(s, &usage, Some(m)),
        None if interrupted_terminal => tracker.response_interrupted(&usage),
        None => {
            acct.record_ok();
            tracker.finish(200, &usage, None)
        }
    }
    Native::Done
}

#[cfg(test)]
#[path = "ws/interrupt_tests.rs"]
mod interrupt_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountState, Credential, OAuth};
    use parking_lot::{Mutex, RwLock};
    use std::collections::BTreeMap;

    pub(super) fn account() -> Arc<Account> {
        Arc::new(Account {
            id: "test-codex-account".into(),
            provider: Provider::Codex,
            label: "test".into(),
            path: None,
            group: None,
            models: vec![],
            headers: BTreeMap::new(),
            proxy_url: None,
            cred: RwLock::new(Credential::OAuth(OAuth::default())),
            state: Mutex::new(AccountState::default()),
            refresh_lock: tokio::sync::Mutex::new(()),
            device_id: String::new(),
            session_id: String::new(),
            discovered: RwLock::new(vec![]),
            prefix: None,
            excluded: vec![],
            aliases: vec![],
        })
    }

    fn tool_turn() -> (Session, Value, Vec<Value>) {
        let mut sess = Session::default();
        sess.remember(
            "resp_prior".into(),
            vec![
                json!({ "role": "user", "content": "Read the tests" }),
                json!({ "type": "function_call", "call_id": "call_tests", "name": "read_tests", "arguments": "{}" }),
            ],
        );
        sess.remember_upstream("resp_prior".into());
        let body = json!({
            "model": "gpt-6.1-sol", "previous_response_id": "resp_prior",
            "reasoning": { "effort": "max" }, "stream": true,
            "input": [{ "type": "function_call_output", "call_id": "call_tests", "output": "All tests pass" }]
        });
        let mut full = sess.lookup("resp_prior").unwrap();
        full.extend(input_items(&body));
        (sess, body, full)
    }

    #[test]
    fn warmups_and_subscription_only_requests_never_use_generation_fallback() {
        let mut cfg = Config::default();
        assert!(matches!(unavailable(&cfg, &json!({ "generate": false }), "connect failed"), Native::Error(502, _)));
        assert!(matches!(unavailable(&cfg, &json!({ "generate": true }), "connect failed"), Native::Fallback));
        cfg.codex_subscription_only = true;
        assert!(matches!(unavailable(&cfg, &json!({ "generate": true }), "connect failed"), Native::Error(502, _)));
    }

    #[test]
    fn reconnect_replays_prior_tool_call_and_new_tool_result() {
        let (sess, body, full) = tool_turn();
        let replay = prepare_native_body(&sess, &body, &full, "gpt-6.1-sol", true, None).unwrap();
        assert!(replay.get("previous_response_id").is_none());
        assert!(replay.get("stream").is_none());
        assert_eq!(replay["input"], Value::Array(full));
        assert_eq!(replay["input"][1]["call_id"], "call_tests");
        assert_eq!(replay["input"][2]["call_id"], "call_tests");
        assert_eq!(replay["reasoning"]["effort"], "max");
        assert_eq!(body["previous_response_id"], "resp_prior");
    }

    #[test]
    fn existing_connection_keeps_incremental_input_and_warmup_flag() {
        let (sess, mut body, full) = tool_turn();
        body["generate"] = false.into();
        let payload = prepare_native_body(&sess, &body, &full, "gpt-6.1-sol", false, None).unwrap();
        assert_eq!(payload["previous_response_id"], "resp_prior");
        assert_eq!(payload["input"], body["input"]);
        assert_eq!(payload["generate"], false);
    }

    #[test]
    fn http_response_ids_replay_even_when_native_connection_is_reused() {
        let (mut sess, body, full) = tool_turn();
        sess.upstream_ids.clear();
        let payload = prepare_native_body(&sess, &body, &full, "gpt-6.1-sol", false, None).unwrap();
        assert!(payload.get("previous_response_id").is_none());
        assert_eq!(payload["input"], Value::Array(full));
    }

    #[test]
    fn reconnect_rejects_an_unknown_previous_id_instead_of_losing_context() {
        let (mut sess, body, full) = tool_turn();
        sess.history.clear();
        let error = prepare_native_body(&sess, &body, &full, "gpt-6.1-sol", true, None).unwrap_err();
        assert_eq!(error["error"]["code"], "previous_response_not_found");
    }

    #[test]
    fn upstream_reuse_requires_the_current_pool_account() {
        let saved = account();
        assert!(current_account_can_reuse(Some(&saved), &saved, "gpt-6.1-sol", None, false));
        assert!(!current_account_can_reuse(None, &saved, "gpt-6.1-sol", None, false));
        let replaced = account();
        assert!(!current_account_can_reuse(Some(&replaced), &saved, "gpt-6.1-sol", None, false));
        saved.state.lock().disabled = true;
        assert!(!current_account_can_reuse(Some(&saved), &saved, "gpt-6.1-sol", None, false));
    }

    #[test]
    fn response_done_is_a_completion_and_preserves_full_history() {
        let mut event = json!({ "type": "response.done", "response": {
            "id": "resp_done", "output": [{ "role": "assistant", "content": "Done" }]
        }});
        assert!(normalize_completion(&mut event));
        assert_eq!(event["type"], "response.completed");
        let mut sess = Session::default();
        let input = vec![json!({ "role": "user", "content": "Run the tests" })];
        assert_eq!(capture(&mut sess, &event, &input, &TurnOutput::default()).as_deref(), Some("resp_done"));
        let history = sess.lookup("resp_done").unwrap();
        assert_eq!(history[0], input[0]);
        assert_eq!(history[1]["content"], "Done");
    }

    #[test]
    fn empty_completion_replays_streamed_reasoning_tool_call_and_tool_result() {
        let reasoning = json!({
            "type": "reasoning", "id": "rs_streamed",
            "encrypted_content": "opaque-reasoning-for-replay",
            "summary": [{ "type": "summary_text", "text": "Read the tests first" }],
            "additional_replay_field": { "preserve": true }
        });
        let tool_call = json!({
            "type": "function_call", "id": "fc_streamed", "call_id": "call_tests",
            "name": "read_tests", "arguments": "{}", "status": "completed"
        });
        let mut output = TurnOutput::default();
        // Arrival order must not change output order, and raw fields must survive.
        output.observe(&json!({ "type": "response.output_item.done", "output_index": 1, "item": tool_call }), None);
        output.observe(&json!({ "type": "response.output_item.done", "output_index": 0, "item": reasoning }), None);
        let original_input = vec![json!({ "role": "user", "content": "Read the tests" })];
        for response in [json!({ "id": "resp_streamed", "output": [] }), json!({ "id": "resp_streamed" })] {
            let completion = json!({ "type": "response.completed", "response": response });
            let wire_event = completion.clone();
            let mut sess = Session::default();
            assert_eq!(capture(&mut sess, &completion, &original_input, &output).as_deref(), Some("resp_streamed"));
            assert_eq!(completion, wire_event);
            let mut full = sess.lookup("resp_streamed").unwrap();
            assert_eq!(full, vec![original_input[0].clone(), reasoning.clone(), tool_call.clone()]);

            let next = json!({
                "model": "gpt-6.1-sol", "previous_response_id": "resp_streamed",
                "input": [{ "type": "function_call_output", "call_id": "call_tests", "output": "All tests pass" }]
            });
            full.extend(input_items(&next));
            let replay = prepare_native_body(&sess, &next, &full, "gpt-6.1-sol", true, None).unwrap();
            assert!(replay.get("previous_response_id").is_none());
            assert_eq!(replay["input"][1]["encrypted_content"], reasoning["encrypted_content"]);
            assert_eq!(replay["input"][1]["additional_replay_field"], reasoning["additional_replay_field"]);
            assert_eq!(replay["input"][2]["type"], "function_call");
            assert_eq!(replay["input"][2]["call_id"], "call_tests");
            assert_eq!(replay["input"][3]["type"], "function_call_output");
            assert_eq!(replay["input"][3]["call_id"], "call_tests");
        }
    }

    #[test]
    fn named_sse_item_events_supply_missing_incomplete_output() {
        let item =
            json!({ "type": "custom_tool_call", "call_id": "call_patch", "name": "apply_patch", "input": "patch" });
        let mut output = TurnOutput::default();
        output.observe(&json!({ "output_index": 0, "item": item }), Some("response.output_item.done"));
        let event = json!({ "type": "response.incomplete", "response": { "id": "resp_incomplete" } });
        let mut sess = Session::default();
        let _ = capture(&mut sess, &event, &[], &output);
        assert_eq!(sess.lookup("resp_incomplete").unwrap(), vec![item]);
    }

    #[test]
    fn nonempty_final_output_takes_precedence_over_streamed_items() {
        let mut output = TurnOutput::default();
        output.observe(
            &json!({
                "type": "response.output_item.done", "output_index": 0,
                "item": { "type": "message", "content": "Streamed" }
            }),
            None,
        );
        let final_item = json!({ "type": "message", "content": "Authoritative final output" });
        let response = json!({ "output": [final_item] });
        assert_eq!(output.captured_items(&response), vec![final_item]);
    }

    pub(super) async fn admission_socket() -> (Upstream, tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/responses", listener.local_addr().unwrap());
        let (client, server) = tokio::join!(tokio_tungstenite::connect_async(url), async {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(socket).await.unwrap()
        });
        (client.unwrap().0, server)
    }

    pub(super) fn admission_app() -> (Arc<App>, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(format!("cliproxy-idle-admission-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let config = Config { auth_dir: directory.to_string_lossy().into(), ..Default::default() };
        (App::new(config, directory.join("config.yaml")), directory)
    }

    #[tokio::test]
    async fn pending_subscription_admission_answers_ping_and_retires_close_without_losing_history() {
        let (upstream, mut peer) = admission_socket().await;
        let (app, directory) = admission_app();
        let mut sess = Session { upstream: Some((account(), upstream)), ..Default::default() };
        sess.remember("resp_prior".into(), vec![json!({"type":"function_call", "call_id":"call_prior"})]);
        sess.remember_upstream("resp_prior".into());
        let (complete, allowance) = tokio::sync::oneshot::channel();
        let app_for_wait = app.clone();
        let waiting = tokio::spawn(async move {
            while_idle(&app_for_wait, &mut sess, allowance).await.unwrap();
            sess
        });
        peer.send(tungstenite::Message::Ping(b"allowance-pending".to_vec().into())).await.unwrap();
        let pong = tokio::time::timeout(Duration::from_secs(1), peer.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(pong, tungstenite::Message::Pong(b"allowance-pending".to_vec().into()));
        assert!(!waiting.is_finished(), "allowance must still be pending when Pong arrives");
        peer.close(None).await.unwrap();
        let close = tokio::time::timeout(Duration::from_secs(1), peer.next()).await.unwrap().unwrap().unwrap();
        assert!(matches!(close, tungstenite::Message::Close(_)));
        complete.send(()).unwrap();
        let sess = waiting.await.unwrap();
        assert!(sess.upstream.is_none());
        assert!(sess.upstream_ids.is_empty());
        assert_eq!(sess.lookup("resp_prior").unwrap()[0]["call_id"], "call_prior");
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn subscription_admission_completion_drains_a_simultaneously_ready_close() {
        let (upstream, mut peer) = admission_socket().await;
        let (app, directory) = admission_app();
        let mut sess = Session { upstream: Some((account(), upstream)), ..Default::default() };
        sess.remember("resp_prior".into(), vec![json!({"role":"user", "content":"prior"})]);
        sess.remember_upstream("resp_prior".into());
        peer.close(None).await.unwrap();
        let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = sess.upstream.as_ref().unwrap().1.get_ref() else {
            panic!("local test must use plaintext TCP");
        };
        tokio::time::timeout(Duration::from_secs(1), tcp.readable()).await.unwrap().unwrap();
        while_idle(&app, &mut sess, std::future::ready(())).await;
        assert!(sess.upstream.is_none(), "ready allowance must not hide a queued Close");
        assert!(sess.upstream_ids.is_empty());
        assert!(sess.lookup("resp_prior").is_some());
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use tokio::io::{DuplexStream, duplex};
    use tokio_tungstenite::WebSocketStream;
    use tungstenite::protocol::Role;

    async fn blocked_upstream() -> (WebSocketStream<DuplexStream>, DuplexStream) {
        let (socket, peer) = duplex(1);
        (WebSocketStream::from_raw_socket(socket, Role::Client, None).await, peer)
    }

    #[tokio::test]
    async fn ready_upstream_close_is_drained_before_submitting_next_turn() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut peer = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        // Buffered server Ping and normal Close make readiness independent of network scheduling.
        let up = WebSocketStream::from_partially_read(
            tokio_tungstenite::MaybeTlsStream::Plain(client),
            vec![0x89, 1, b'p', 0x88, 2, 0x03, 0xe8],
            Role::Client,
            None,
        )
        .await;
        let pool = crate::accounts::Pool::default();
        pool.reload(&crate::config::Config {
            auth_dir: "/nonexistent".into(),
            codex_api_key: vec![crate::config::KeyEntry { api_key: "local-mock".into(), ..Default::default() }],
            ..Default::default()
        });
        let acct = pool.all().pop().unwrap();
        let app = App::new(
            Config { auth_dir: "/nonexistent".into(), ..Default::default() },
            "/nonexistent/config.yaml".into(),
        );
        let mut sess = Session {
            upstream: Some((acct, up)),
            upstream_ids: VecDeque::from(["prior-response".into()]),
            pinned: Some("retained-session".into()),
            ..Default::default()
        };
        tokio::time::timeout(Duration::from_secs(1), drain_idle_upstream(&app, &mut sess)).await.unwrap();
        assert!(sess.upstream.is_none());
        assert!(sess.upstream_ids.is_empty());
        assert_eq!(sess.pinned.as_deref(), Some("retained-session"));
        let pong = tokio::time::timeout(Duration::from_secs(1), peer.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(pong, tungstenite::Message::Pong(vec![b'p'].into()));
        let close = tokio::time::timeout(Duration::from_secs(1), peer.next()).await.unwrap().unwrap().unwrap();
        assert!(matches!(close, tungstenite::Message::Close(_)));
    }

    #[tokio::test]
    async fn upstream_send_flush_and_close_stop_at_write_deadline() {
        let (mut sender, _sender_peer) = blocked_upstream().await;
        let (mut flusher, _flusher_peer) = blocked_upstream().await;
        let (mut closer, _closer_peer) = blocked_upstream().await;
        let (mut interrupter, _interrupt_peer) = blocked_upstream().await;
        // Feed queues a frame; the unread one-byte transport blocks its flush.
        flusher.feed(tungstenite::Message::Text("queued request".into())).await.unwrap();
        let started = tokio::time::Instant::now();
        let failures = tokio::time::timeout(UPSTREAM_WRITE_TIMEOUT + Duration::from_secs(3), async {
            futures::join!(
                upstream_write("send", sender.send(tungstenite::Message::Text("submitted request".into()))),
                upstream_write("flush", flusher.flush()),
                upstream_write("close", closer.close(None)),
                upstream_write("interrupt", interrupter.send(tungstenite::Message::Text("control".into()))),
            )
        })
        .await
        .expect("blocked websocket writes outlived their deadline");
        assert!(started.elapsed() >= UPSTREAM_WRITE_TIMEOUT);
        for (operation, result) in
            [("send", failures.0), ("flush", failures.1), ("close", failures.2), ("interrupt", failures.3)]
        {
            let failure = result.expect_err("an unread duplex transport must block");
            assert_eq!(failure.status, 504);
            assert_eq!(failure.operation, operation);
            assert_eq!(failure.message, format!("codex websocket {operation} timed out"));
        }
    }

    #[test]
    fn upstream_failure_diagnostics_exclude_frames_credentials_bodies_and_urls() {
        let secret = "private-prompt-token-account";
        let errors = [
            tungstenite::Error::WriteBufferFull(tungstenite::Message::Text(secret.into())),
            tungstenite::Error::Utf8(secret.into()),
            tungstenite::Error::Url(tungstenite::error::UrlError::UnableToConnect(secret.into())),
            tungstenite::Error::Io(std::io::Error::other(secret)),
            tungstenite::Error::Http(
                tungstenite::http::Response::builder()
                    .status(403)
                    .header("authorization", secret)
                    .body(Some(secret.as_bytes().to_vec()))
                    .unwrap(),
            ),
        ];
        for error in errors {
            let failure = UpstreamFailure::socket("send", &error);
            assert_eq!(failure.status, 502);
            assert!(!failure.message.contains(secret));
            assert!(failure.message.starts_with("codex websocket send failed:"));
        }
        let error = tungstenite::Error::Protocol(tungstenite::error::ProtocolError::ResetWithoutClosingHandshake);
        assert!(UpstreamFailure::socket("read", &error).message.contains("Connection reset without closing handshake"));
    }
}
