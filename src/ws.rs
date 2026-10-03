//! Responses API over websocket (`GET /v1/responses`), the transport Codex uses.
//!
//! Each `response.create` message is one turn. Codex OAuth accounts get a
//! native upstream websocket (server-side `previous_response_id` works as-is);
//! every other provider is served through the normal pipeline, with
//! `previous_response_id` expanded from a small local history.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::http::HeaderMap;
use futures::{SinkExt, StreamExt};
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

const HISTORY: usize = 4;

#[derive(Default)]
struct Session {
    /// response id -> full conversation input including that response's output.
    history: VecDeque<(String, Vec<Value>)>,
    upstream: Option<(Arc<Account>, Upstream)>,
    /// IDs created on the current upstream connection, excluding HTTP turns.
    upstream_ids: VecDeque<String>,
    pinned: Option<String>,
}

impl Session {
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
        if let Some(output) = response["output"].as_array().filter(|output| !output.is_empty()) {
            output.clone()
        } else {
            // Codex can put all output in item.done events and leave the final
            // response output empty. Reconstruct history without changing wire events.
            self.items.values().cloned().collect()
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
    let (mut tx, mut rx) = socket.split();
    let mut sess = Session::default();
    while let Some(msg) = rx.next().await {
        let text = match msg {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Binary(b)) => String::from_utf8_lossy(&b).into_owned(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        let request_id = app.stats.next_id();
        audit(
            &app,
            request_id,
            "downstream_request",
            serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text.clone())),
        );
        let Ok(mut body) = serde_json::from_str::<Value>(&text) else {
            if send(&app, request_id, &mut tx, error_event(400, &json!({ "error": { "message": "invalid JSON" } })))
                .await
                .is_err()
            {
                break;
            }
            continue;
        };
        if body["type"] != "response.create" {
            let msg = format!("unsupported message type `{}`", body["type"].as_str().unwrap_or_default());
            if send(
                &app,
                request_id,
                &mut tx,
                error_event(400, &json!({ "error": { "message": msg, "type": "invalid_request_error" } })),
            )
            .await
            .is_err()
            {
                break;
            }
            continue;
        }
        if let Some(o) = body.as_object_mut() {
            o.remove("type");
        }
        if turn(&app, request_id, &headers, &mut sess, body, &mut tx).await.is_err() {
            break;
        }
    }
    if let Some((_, mut up)) = sess.upstream.take() {
        let _ = up.close(None).await;
    }
}

async fn turn(
    app: &Arc<App>,
    request_id: u64,
    headers: &HeaderMap,
    sess: &mut Session,
    mut body: Value,
    tx: &mut ClientTx,
) -> Result<(), ClientGone> {
    // Full conversation for local history (and for providers without server state).
    let prev = body["previous_response_id"].as_str().map(String::from);
    let mut full = prev.as_deref().and_then(|id| sess.lookup(id)).unwrap_or_default();
    full.extend(input_items(&body));

    let cfg = app.cfg();
    if cfg.codex_websockets {
        match native_turn(app, request_id, headers, sess, &body, &full, tx).await {
            Native::Done => return Ok(()),
            Native::Gone => return Err(ClientGone),
            Native::Fallback => {}
            Native::Error(status, error) => return send(app, request_id, tx, error_event(status, &error)).await,
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
        return send(app, request_id, tx, error_event(status, &error)).await;
    }

    if let Some(id) = &prev {
        if sess.lookup(id).is_none() {
            return send(app, request_id, tx, error_event(400, &previous_missing())).await;
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
        Reply::Stream { mut frames, .. } => {
            let mut output = TurnOutput::default();
            while let Some(mut f) = frames.next().await {
                let mut event = serde_json::from_str::<Value>(&f.data).unwrap_or(Value::Null);
                output.observe(&event, f.event.as_deref());
                if normalize_completion(&mut event) {
                    f.data = event.to_string();
                }
                if matches!(event["type"].as_str(), Some("response.completed" | "response.incomplete"))
                    || matches!(f.event.as_deref(), Some("response.completed" | "response.incomplete"))
                {
                    let _ = capture(sess, &event, &full, &output);
                }
                send(app, request_id, tx, f.data).await?;
            }
            Ok(())
        }
        Reply::Json(v) => {
            let _ = capture(sess, &json!({ "response": v }), &full, &TurnOutput::default());
            send(app, request_id, tx, json!({ "type": "response.completed", "response": v }).to_string()).await
        }
        Reply::Error(status, body) => send(app, request_id, tx, error_event(status, &body)).await,
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
    tx: &mut ClientTx,
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
        if let Some((_, mut up)) = sess.upstream.take() {
            let _ = up.close(None).await;
        }
        sess.upstream_ids.clear();
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
    let (acct, mut up) = sess.upstream.take().unwrap();
    let upstream_model = acct.resolve(&model).unwrap_or(model.clone());
    if reuse {
        tracker.attempt(&acct);
    }
    // Recheck subscription allowance for every turn, after any handshake quota
    // update and before sending a payload on either a new or reused connection.
    if let Err(e) = crate::quota::require_subscription(app, &acct, &upstream_model).await {
        let message = e.to_string();
        let _ = up.close(None).await;
        sess.upstream_ids.clear();
        tracker.finish(403, &Usage::default(), Some(message.clone()));
        return Native::Error(
            403,
            json!({ "error": { "message": message, "type": "permission_error", "code": "subscription_required" } }),
        );
    }
    let payload = match prepare_native_body(sess, body, full, &upstream_model, !reuse, suffix.as_ref()) {
        Ok(payload) => payload,
        Err(error) => {
            sess.upstream = Some((acct, up));
            tracker.finish(400, &Usage::default(), Some(proxy::error_message(&error.to_string())));
            return Native::Error(400, error);
        }
    };
    audit(app, tracker.id(), "upstream_request", payload.clone());
    if up.send(tungstenite::Message::Text(payload.to_string().into())).await.is_err() {
        sess.upstream_ids.clear();
        return tracked_unavailable(&mut tracker, &cfg, body, "websocket send failed");
    }

    let mut parser = responses::Parser::default();
    let mut output = TurnOutput::default();
    let mut usage = Usage::default();
    let mut evs = Vec::new();
    let mut error: Option<(u16, String)> = None;
    let mut forwarded = false;
    let mut terminal = false;
    loop {
        let next = tokio::time::timeout(std::time::Duration::from_secs(600), up.next()).await;
        let mut text = match next {
            Ok(Some(Ok(tungstenite::Message::Text(t)))) => t.to_string(),
            Ok(Some(Ok(tungstenite::Message::Binary(b)))) => String::from_utf8_lossy(&b).into_owned(),
            Ok(Some(Ok(tungstenite::Message::Close(_)))) | Ok(None) => {
                error = Some((502, "codex websocket closed".into()));
                break;
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => {
                error = Some((502, format!("codex websocket error: {e}")));
                break;
            }
            Err(_) => {
                error = Some((504, "codex websocket idle timeout".into()));
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
            let _ = up.close(None).await;
            sess.pinned = None;
            sess.upstream_ids.clear();
            if !cfg.codex_subscription_only && !is_warmup(body) {
                tracker.cancel();
                return Native::Fallback;
            }
            tracker.finish(status, &usage, Some(msg));
            return if send(app, tracker.id(), tx, text).await.is_err() { Native::Gone } else { Native::Done };
        }
        if (kind == "response.completed" || kind == "response.incomplete")
            && let Some(id) = capture(sess, &v, full, &output)
        {
            sess.remember_upstream(id);
        }
        terminal = matches!(kind.as_str(), "response.completed" | "response.incomplete" | "response.failed" | "error");
        forwarded = true;
        if send(app, tracker.id(), tx, text).await.is_err() {
            tracker.finish(499, &usage, Some("client disconnected".into()));
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
        if send(app, tracker.id(), tx, error_event(status, &body)).await.is_err() {
            tracker.finish(status, &usage, Some(msg));
            return Native::Gone;
        }
    }
    match error {
        Some((s, m)) => tracker.finish(s, &usage, Some(m)),
        None => {
            acct.record_ok();
            tracker.finish(200, &usage, None)
        }
    }
    Native::Done
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{AccountState, Credential, OAuth};
    use parking_lot::{Mutex, RwLock};
    use std::collections::BTreeMap;

    fn account() -> Arc<Account> {
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
}
