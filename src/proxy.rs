//! Request pipeline: pick an account, translate, send, retry, stream back.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use futures::{Stream, StreamExt};
use serde_json::{Value, json};

use crate::accounts::{Account, Pick, Provider};
use crate::formats::{self, Frame};
use crate::ir::{self, Aggregate, Event, Format, Reasoning, Request, Usage};
use crate::sse::SseDecoder;
use crate::state::{App, RequestLog};
use crate::upstream::{self, Target};

pub type FrameStream = Pin<Box<dyn Stream<Item = Frame> + Send>>;

pub struct Call {
    pub format: Format,
    pub body: Value,
    pub headers: HeaderMap,
    pub stream: bool,
    pub transport: &'static str,
    /// Model from the URL (Gemini routes).
    pub path_model: Option<String>,
    /// Prefer this account (websocket session affinity).
    pub pinned: Option<String>,
}

pub enum Reply {
    Stream { frames: FrameStream, account: String },
    Json(Value),
    Error(u16, Value),
}

// --------------------------------------------------------------------- tracker

/// Records the request in stats when finished (or dropped mid-stream).
pub struct Tracker {
    app: Arc<App>,
    log: RequestLog,
    started: Instant,
    acct: Option<Arc<Account>>,
    done: bool,
}

impl Tracker {
    pub fn new(app: &Arc<App>, client: Format, stream: bool, transport: &'static str, model: &str) -> Self {
        app.stats.active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            app: app.clone(),
            started: Instant::now(),
            acct: None,
            done: false,
            log: RequestLog {
                id: app.stats.next_id(),
                ts: Utc::now(),
                client: client.as_str(),
                provider: String::new(),
                model: model.to_string(),
                account: String::new(),
                status: 0,
                latency_ms: 0,
                ttft_ms: None,
                input_tokens: 0,
                output_tokens: 0,
                cache_tokens: 0,
                stream,
                transport,
                attempts: 0,
                error: None,
            },
        }
    }

    pub fn attempt(&mut self, acct: &Arc<Account>) {
        self.log.attempts += 1;
        self.log.provider = acct.provider.as_str().to_string();
        self.log.account = acct.label.clone();
        self.acct = Some(acct.clone());
    }

    /// Drops the tracker without recording a request.
    pub fn cancel(&mut self) {
        if !self.done {
            self.done = true;
            self.app.stats.active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn first_token(&mut self) {
        if self.log.ttft_ms.is_none() {
            self.log.ttft_ms = Some(self.started.elapsed().as_millis() as u64);
        }
    }

    pub fn finish(&mut self, status: u16, usage: &Usage, error: Option<String>) {
        if self.done {
            return;
        }
        self.done = true;
        self.app.stats.active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let (input, output, cache) = crate::state::usage_tokens(usage);
        self.log.status = status;
        self.log.latency_ms = self.started.elapsed().as_millis() as u64;
        self.log.input_tokens = input;
        self.log.output_tokens = output;
        self.log.cache_tokens = cache;
        self.log.error = error.map(|e| e.chars().take(400).collect());
        if let Some(a) = &self.acct {
            let mut st = a.state.lock();
            st.counters.requests += 1;
            if status >= 400 {
                st.counters.failures += 1;
            }
            st.counters.input_tokens += input;
            st.counters.output_tokens += output;
            st.counters.cache_tokens += cache;
            st.last_used = Some(Utc::now());
        }
        self.app.stats.record(&self.log);
        self.app.broadcast("request", &self.log);
        tracing::info!(
            target: "cliproxyapi_rust::request",
            "{} {} → {} [{}] {} {}ms in={} out={}",
            self.log.client, self.log.model, self.log.provider, self.log.account, status,
            self.log.latency_ms, input, output
        );
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        if !self.done {
            self.finish(499, &Usage::default(), Some("client disconnected".into()));
        }
    }
}

// -------------------------------------------------------------------- pipeline

fn error_reply(format: Format, status: u16, msg: &str) -> Reply {
    Reply::Error(status, formats::error_body(format, status, msg))
}

/// Pulls a human readable message out of an upstream error body.
pub fn error_message(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        let e = if v["error"].is_object() { &v["error"] } else { &v };
        for k in ["message", "detail", "error_description"] {
            if let Some(m) = e[k].as_str() {
                return m.to_string();
            }
        }
        if let Some(m) = v["error"].as_str() {
            return m.to_string();
        }
    }
    let t = body.trim();
    if t.is_empty() { "upstream error".into() } else { t.chars().take(500).collect() }
}

/// When the upstream told us its quota resets.
fn reset_after(headers: &reqwest::header::HeaderMap, body: &str) -> Option<chrono::DateTime<Utc>> {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
    if let Some(s) = h("retry-after").and_then(|s| s.parse::<i64>().ok()) {
        return Some(Utc::now() + Duration::seconds(s.clamp(1, 6 * 3600)));
    }
    if let Some(ts) = h("anthropic-ratelimit-unified-reset").and_then(|s| s.parse::<i64>().ok()) {
        return chrono::DateTime::from_timestamp(ts, 0);
    }
    let v: Value = serde_json::from_str(body).ok()?;
    let e = &v["error"];
    if let Some(s) = e["resets_in_seconds"].as_i64() {
        return Some(Utc::now() + Duration::seconds(s.max(1)));
    }
    if let Some(t) = e["resets_at"].as_i64() {
        return chrono::DateTime::from_timestamp(t, 0);
    }
    // Google: {"details": [{"@type": "...RetryInfo", "retryDelay": "3.5s"}]}
    for d in e["details"].as_array().into_iter().flatten() {
        if let Some(delay) = d["retryDelay"].as_str().and_then(|s| s.trim_end_matches('s').parse::<f64>().ok()) {
            return Some(Utc::now() + Duration::milliseconds((delay * 1000.0).max(1000.0) as i64));
        }
        if let Some(ts) = d["metadata"]["quotaResetTimeStamp"].as_str()
            && let Ok(t) = chrono::DateTime::parse_from_rfc3339(ts)
        {
            return Some(t.with_timezone(&Utc));
        }
    }
    None
}

/// A failure worth retrying on the same account, and how long to wait first:
/// capacity errors (Google's "No capacity available") and rate limits that
/// reset within seconds. Real quota exhaustion is not one of them.
fn soft_failure(
    provider: Provider,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Option<std::time::Duration> {
    let short = |until: chrono::DateTime<Utc>| {
        let secs = (until - Utc::now()).num_milliseconds().max(0) as u64;
        (secs <= 10_000).then(|| std::time::Duration::from_millis(secs))
    };
    match status {
        500 | 502 | 503 | 504 | 529 => Some(std::time::Duration::ZERO),
        429 => {
            if body.contains("QUOTA_EXHAUSTED") {
                return None;
            }
            match reset_after(headers, body) {
                Some(until) => short(until),
                // Google answers bursts with a bare RESOURCE_EXHAUSTED while quota is left.
                None if matches!(provider, Provider::Antigravity | Provider::Gemini | Provider::Vertex) => {
                    Some(std::time::Duration::ZERO)
                }
                None => None,
            }
        }
        _ => None,
    }
}

/// Responses backends that understand freeform `custom` tools.
fn native_custom_tools(p: Provider) -> bool {
    matches!(p, Provider::Codex | Provider::Compat)
}

/// 403s that a token refresh won't fix (region / plan / ToS blocks).
fn forbidden_for_good(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    ["not available in your", "unsupported_country", "permission_denied", "terms of service"]
        .iter()
        .any(|k| b.contains(k))
}

fn backoff(acct: &Account) -> chrono::DateTime<Utc> {
    let mut st = acct.state.lock();
    st.strikes = st.strikes.saturating_add(1);
    let secs = (30u64 << (st.strikes - 1).min(6)).min(30 * 60);
    Utc::now() + Duration::seconds(secs as i64)
}

/// Applies a `model(effort)` suffix to a body that is passed through untouched.
fn apply_native_reasoning(format: Format, body: &mut Value, r: &Reasoning, model: &str) {
    match format {
        Format::Chat => {
            if let Some(e) = r.effort_level() {
                body["reasoning_effort"] = e.into();
            }
        }
        Format::Responses => {
            if let Some(e) = r.effort_level() {
                body["reasoning"]["effort"] = e.into();
            }
        }
        Format::Claude => {
            if r.disabled {
                body["thinking"] = json!({ "type": "disabled" });
            } else if formats::claude::uses_budget_thinking(model) {
                if let Some(b) = r.budget_tokens() {
                    let max = body["max_tokens"].as_u64().unwrap_or(formats::claude::default_max_tokens(model));
                    body["thinking"] =
                        json!({ "type": "enabled", "budget_tokens": b.min(max.saturating_sub(1024)).max(1024) });
                }
            } else if let Some(e) = r.effort_level() {
                body["thinking"] = json!({ "type": "adaptive" });
                body["output_config"]["effort"] = e.into();
            }
        }
        Format::Gemini => {
            let tc = &mut body["generationConfig"]["thinkingConfig"];
            if model.starts_with("gemini-3") {
                if let Some(e) = r.effort_level() {
                    tc["thinkingLevel"] = (if e == "low" || e == "minimal" { "low" } else { "high" }).into();
                }
            } else if r.disabled {
                tc["thinkingBudget"] = 0.into();
            } else if let Some(b) = r.budget_tokens() {
                tc["thinkingBudget"] = b.into();
            }
        }
    }
}

/// OpenAI and Gemini limit tool names to 64 characters.
fn shorten_tool_names(req: &mut Request) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut short = |name: &mut String| {
        if name.len() <= 64 {
            return;
        }
        use sha2::{Digest, Sha256};
        let h = hex::encode(Sha256::digest(name.as_bytes()));
        let mut cut = 55;
        while !name.is_char_boundary(cut) {
            cut -= 1;
        }
        let s = format!("{}_{}", &name[..cut], &h[..8]);
        map.insert(s.clone(), name.clone());
        *name = s;
    };
    for t in &mut req.tools {
        short(&mut t.name);
    }
    for n in &mut req.custom_tools {
        short(n);
    }
    if let ir::ToolChoice::Tool(n) = &mut req.tool_choice {
        short(n);
    }
    for m in &mut req.messages {
        for p in &mut m.parts {
            if let ir::Part::ToolCall { name, .. } = p {
                short(name);
            }
        }
    }
    map
}

pub async fn execute(app: Arc<App>, call: Call) -> Reply {
    let cfg = app.cfg();
    let raw_model =
        call.path_model.clone().or_else(|| call.body["model"].as_str().map(String::from)).unwrap_or_default();
    if raw_model.is_empty() {
        return error_reply(call.format, 400, "`model` is required");
    }
    let (model, suffix) = ir::split_model_suffix(&raw_model);
    let (only, model) = app.pool.route(&model);
    let model = app.pool.canonical(&model, only.as_ref());
    let mut tracker = Tracker::new(&app, call.format, call.stream, call.transport, &model);

    let mut parsed: Option<Request> = None;
    let mut tried: Vec<String> = Vec::new();
    let mut refreshed: Vec<String> = Vec::new();
    let mut last_error: Option<(u16, Value)> = None;
    let mut retry_same: Option<String> = None;
    // Same-account retries for blips (capacity errors, soft rate limits).
    let mut soft_tries: HashMap<String, u32> = HashMap::new();
    let attempts = cfg.request_retry.max(1) as usize;

    while tried.len() < attempts {
        let pin = retry_same.take().or_else(|| call.pinned.clone());
        let (acct, upstream_model) = match app.pool.pick(&model, &tried, cfg.routing, pin.as_deref(), only.as_ref()) {
            Pick::Ok(a, m) => (a, m),
            Pick::Cooling(until) => {
                if let Some((s, b)) = last_error {
                    tracker.finish(s, &Usage::default(), Some(error_message(&b.to_string())));
                    return Reply::Error(s, b);
                }
                let msg = format!(
                    "all accounts for {model} are rate limited; next available in {}s",
                    (until - Utc::now()).num_seconds().max(1)
                );
                tracker.finish(429, &Usage::default(), Some(msg.clone()));
                return error_reply(call.format, 429, &msg);
            }
            Pick::None => break,
        };
        tracker.attempt(&acct);

        if let Err(e) = crate::oauth::ensure_ready(&app, &acct).await {
            tracing::warn!(account = %acct.label, "refresh failed: {e:#}");
            acct.cool(None, Utc::now() + Duration::minutes(5), &format!("token refresh failed: {e}"));
            tried.push(acct.id.clone());
            last_error = Some((401, formats::error_body(call.format, 401, &format!("token refresh failed: {e}"))));
            continue;
        }

        if let Err(e) = crate::quota::require_subscription(&app, &acct, &model).await {
            let msg = format!("subscription-only request refused: {e}");
            tracker.finish(429, &Usage::default(), Some(msg.clone()));
            return error_reply(call.format, 429, &msg);
        }

        let provider = acct.provider;
        let devin = provider == Provider::Devin;
        // Freeform (custom) tools only exist on OpenAI's own Responses backends.
        let custom_tools = call.format == Format::Responses
            && call.body["tools"].as_array().is_some_and(|t| t.iter().any(|t| t["type"] == "custom"));
        let passthrough = provider.wires().contains(&call.format) && !(custom_tools && !native_custom_tools(provider));
        let native = if passthrough { call.format } else { provider.wires().first().copied().unwrap_or(Format::Chat) };
        let mut names = HashMap::new();
        let body = if passthrough {
            let mut b = call.body.clone();
            if let Some(r) = &suffix {
                apply_native_reasoning(native, &mut b, r, &upstream_model);
            }
            b
        } else {
            if parsed.is_none() {
                let mut body = call.body.clone();
                if call.format == Format::Gemini {
                    body["model"] = model.clone().into();
                }
                match formats::parse_request(call.format, &body) {
                    Ok(mut r) => {
                        if suffix.is_some() {
                            r.reasoning = suffix.clone();
                        }
                        parsed = Some(r);
                    }
                    Err(e) => {
                        tracker.finish(400, &Usage::default(), Some(e.clone()));
                        return error_reply(call.format, 400, &e);
                    }
                }
            }
            let mut req = parsed.clone().unwrap();
            if native != Format::Claude {
                names = shorten_tool_names(&mut req);
            }
            match native {
                _ if devin => crate::devin::build_request(&req, &upstream_model),
                Format::Claude => formats::claude::build_request(&req, &upstream_model),
                Format::Responses => formats::responses::build_request(
                    &req,
                    &upstream_model,
                    &formats::responses::BuildOpts {
                        chatgpt_backend: provider == Provider::Codex && acct.is_oauth(),
                        custom_tools: native_custom_tools(provider),
                        default_reasoning: provider == Provider::Codex,
                    },
                ),
                Format::Gemini => formats::gemini::build_request(&req, &upstream_model),
                Format::Chat => formats::chat::build_request(&req, &upstream_model),
            }
        };

        // Upstream streaming: always when translating (we re-render), and for Codex OAuth.
        let upstream_stream = !passthrough || call.stream || (provider == Provider::Codex && acct.is_oauth());
        let prepared = upstream::prepare(
            &Target {
                acct: &acct,
                cfg: &cfg,
                client_headers: &call.headers,
                model: &upstream_model,
                wire: native,
                passthrough,
                stream: upstream_stream,
                count_tokens: false,
            },
            body,
        );
        if cfg.debug {
            tracing::debug!(url = %prepared.url, body = %prepared.body, "upstream request");
        }

        let client = app.http.for_account(&acct);
        let mut rb = client.post(&prepared.url);
        for (k, v) in &prepared.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        let payload = prepared.raw.unwrap_or_else(|| serde_json::to_vec(&prepared.body).unwrap_or_default());
        let resp = match rb.body(payload).send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("upstream connection failed: {e}");
                tracing::warn!(account = %acct.label, "{msg}");
                acct.state.lock().last_error = Some(msg.clone());
                // A dropped connection is usually a blip on the provider's side: one more try.
                let n = soft_tries.entry(acct.id.clone()).or_default();
                if *n < 1 {
                    *n += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    retry_same = Some(acct.id.clone());
                    last_error = Some((502, formats::error_body(call.format, 502, &msg)));
                    continue;
                }
                tried.push(acct.id.clone());
                last_error = Some((502, formats::error_body(call.format, 502, &msg)));
                continue;
            }
        };

        let status = resp.status().as_u16();
        crate::quota::observe(&acct, resp.headers());
        if !resp.status().is_success() {
            let headers = resp.headers().clone();
            let text = resp.text().await.unwrap_or_default();
            let msg = error_message(&text);
            tracing::warn!(account = %acct.label, status, "upstream error: {msg}");
            let client_body = if passthrough {
                serde_json::from_str(&text).unwrap_or_else(|_| formats::error_body(call.format, status, &msg))
            } else {
                formats::error_body(call.format, status, &msg)
            };
            if let Some(delay) = soft_failure(provider, status, &headers, &text) {
                let n = soft_tries.entry(acct.id.clone()).or_default();
                if *n < 2 {
                    *n += 1;
                    let wait = delay.max(std::time::Duration::from_secs(if *n == 1 { 1 } else { 3 }));
                    tracing::info!(account = %acct.label, status, "upstream busy, retrying in {}s", wait.as_secs());
                    tokio::time::sleep(wait).await;
                    retry_same = Some(acct.id.clone());
                    last_error = Some((status, client_body));
                    continue;
                }
                // Still busy: step aside briefly, without the escalating backoff.
                if status == 429 {
                    acct.cool(Some(&model), Utc::now() + Duration::seconds(15), &format!("429: {msg}"));
                } else {
                    acct.state.lock().last_error = Some(format!("{status}: {msg}"));
                }
                app.broadcast("accounts", Value::Null);
                tried.push(acct.id.clone());
                last_error = Some((status, client_body));
                continue;
            }
            match status {
                429 => {
                    let until = reset_after(&headers, &text).unwrap_or_else(|| backoff(&acct));
                    acct.cool(Some(&model), until, &format!("429: {msg}"));
                    app.broadcast("accounts", Value::Null);
                }
                401 | 403 if acct.is_oauth() && !refreshed.contains(&acct.id) && !forbidden_for_good(&text) => {
                    refreshed.push(acct.id.clone());
                    if crate::oauth::ensure_fresh(&app, &acct, Duration::minutes(5), true).await.is_ok() {
                        // Retry the same account with the new token.
                        retry_same = Some(acct.id.clone());
                        last_error = Some((status, client_body));
                        continue;
                    }
                    acct.cool(None, Utc::now() + Duration::minutes(10), &format!("{status}: {msg}"));
                }
                401 | 403 => acct.cool(None, Utc::now() + Duration::minutes(10), &format!("{status}: {msg}")),
                400 | 404 | 413 | 422 => {
                    acct.state.lock().last_error = Some(format!("{status}: {msg}"));
                    tracker.finish(status, &Usage::default(), Some(msg));
                    return Reply::Error(status, client_body);
                }
                _ => {
                    acct.state.lock().last_error = Some(format!("{status}: {msg}"));
                }
            }
            tried.push(acct.id.clone());
            last_error = Some((status, client_body));
            continue;
        }

        acct.record_ok();
        // The ChatGPT backend streams without any Content-Type, so a stream we
        // asked for counts as one unless it says it's JSON.
        let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or_default();
        let is_sse = ctype.contains("event-stream") || (upstream_stream && !ctype.contains("json"));
        let account = acct.label.clone();
        let req = Arc::new(parsed.clone().unwrap_or_default());

        let unwrap = provider == Provider::Antigravity;
        if passthrough {
            if call.stream && is_sse {
                return Reply::Stream { frames: passthrough_stream(resp, native, tracker, unwrap), account };
            }
            if is_sse {
                // Codex only streams: rebuild the final response object.
                return collect_passthrough(Box::pin(resp.bytes_stream()), native, tracker, call.format).await;
            }
            let text = resp.text().await.unwrap_or_default();
            let mut v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                // An unlabelled stream after all: rebuild the final object from it.
                Err(_) if text.contains("data:") => {
                    let body = futures::stream::once(async move { Ok(bytes::Bytes::from(text)) });
                    return collect_passthrough(Box::pin(body), native, tracker, call.format).await;
                }
                Err(_) => Value::String(text),
            };
            if unwrap {
                v = crate::antigravity::unwrap(v);
            }
            let mut agg = Aggregate::default();
            formats::full_to_events(native, &v).iter().for_each(|e| agg.push(e));
            tracker.finish(status, &agg.usage, None);
            return Reply::Json(v);
        }

        let events =
            if devin { crate::devin::event_stream(resp, names) } else { event_stream(resp, native, is_sse, names) };
        let client_model = model.clone();
        if call.stream {
            let frames = render_stream(events, call.format, client_model, req, tracker);
            return Reply::Stream { frames, account };
        }
        return collect(events, call.format, &client_model, &req, tracker).await;
    }

    let (status, body) = last_error.unwrap_or_else(|| {
        (404, formats::error_body(call.format, 404, &format!("no available account serves model `{model}`")))
    });
    tracker.finish(status, &Usage::default(), Some(error_message(&body.to_string())));
    Reply::Error(status, body)
}

// -------------------------------------------------------------------- streams

type EventStream = Pin<Box<dyn Stream<Item = Event> + Send>>;

/// Decodes the upstream body into IR events.
fn event_stream(resp: reqwest::Response, native: Format, is_sse: bool, names: HashMap<String, String>) -> EventStream {
    let rename = move |ev: Event| match ev {
        Event::ToolStart { key, id, name } => {
            let name = names.get(&name).cloned().unwrap_or(name);
            Event::ToolStart { key, id, name }
        }
        other => other,
    };
    if !is_sse {
        return Box::pin(async_stream::stream! {
            let text = resp.text().await.unwrap_or_default();
            let evs = match serde_json::from_str::<Value>(&text) {
                Ok(v) => formats::full_to_events(native, &v),
                // Mislabelled stream: decode it as SSE after all.
                Err(_) => {
                    let mut dec = SseDecoder::default();
                    let mut parser = formats::parser(native);
                    let mut out = Vec::new();
                    for sse in dec.push(text.as_bytes()).into_iter().chain(dec.finish()) {
                        parser.feed(&sse, &mut out);
                    }
                    out
                }
            };
            for ev in evs {
                yield rename(ev);
            }
        });
    }
    Box::pin(async_stream::stream! {
        let mut body = resp.bytes_stream();
        let mut dec = SseDecoder::default();
        let mut parser = formats::parser(native);
        let mut out = Vec::new();
        loop {
            match body.next().await {
                Some(Ok(chunk)) => {
                    for sse in dec.push(&chunk) {
                        parser.feed(&sse, &mut out);
                    }
                }
                Some(Err(e)) => {
                    out.push(Event::Error { status: 502, message: format!("upstream stream error: {e}") });
                    for ev in out.drain(..) { yield rename(ev); }
                    return;
                }
                None => {
                    for sse in dec.finish() {
                        parser.feed(&sse, &mut out);
                    }
                    for ev in out.drain(..) { yield rename(ev); }
                    return;
                }
            }
            for ev in out.drain(..) { yield rename(ev); }
        }
    })
}

fn is_content(ev: &Event) -> bool {
    matches!(ev, Event::Text(_) | Event::Reasoning(_) | Event::ToolStart { .. })
}

fn render_stream(
    mut events: EventStream,
    format: Format,
    model: String,
    req: Arc<Request>,
    mut tracker: Tracker,
) -> FrameStream {
    Box::pin(async_stream::stream! {
        let mut renderer = formats::renderer(format, &model, &req);
        let mut usage = Usage::default();
        let mut error: Option<(u16, String)> = None;
        let mut frames = Vec::new();
        while let Some(ev) = events.next().await {
            match &ev {
                Event::Usage(u) => usage.merge(u),
                Event::Error { status, message } => error = Some((*status, message.clone())),
                e if is_content(e) => tracker.first_token(),
                _ => {}
            }
            renderer.push(&ev, &mut frames);
            for f in frames.drain(..) { yield f; }
        }
        renderer.finish(&mut frames);
        for f in frames.drain(..) { yield f; }
        match error {
            Some((s, m)) => tracker.finish(s, &usage, Some(m)),
            None => tracker.finish(200, &usage, None),
        }
    })
}

async fn collect(mut events: EventStream, format: Format, model: &str, req: &Request, mut tracker: Tracker) -> Reply {
    let mut agg = Aggregate::default();
    while let Some(ev) = events.next().await {
        if is_content(&ev) {
            tracker.first_token();
        }
        agg.push(&ev);
    }
    if let Some((status, msg)) = agg.error.clone() {
        tracker.finish(status, &agg.usage, Some(msg.clone()));
        return error_reply(format, status, &msg);
    }
    tracker.finish(200, &agg.usage, None);
    Reply::Json(formats::render_full(format, &agg, model, req))
}

/// Forwards upstream SSE events untouched while tapping usage.
fn passthrough_stream(resp: reqwest::Response, native: Format, mut tracker: Tracker, unwrap: bool) -> FrameStream {
    Box::pin(async_stream::stream! {
        let mut body = resp.bytes_stream();
        let mut dec = SseDecoder::default();
        let mut parser = formats::parser(native);
        let mut usage = Usage::default();
        let mut error: Option<(u16, String)> = None;
        let mut evs = Vec::new();
        loop {
            let (batch, end) = match body.next().await {
                Some(Ok(chunk)) => (dec.push(&chunk), false),
                Some(Err(e)) => {
                    error = Some((502, format!("upstream stream error: {e}")));
                    (dec.finish(), true)
                }
                None => (dec.finish(), true),
            };
            for sse in batch {
                parser.feed(&sse, &mut evs);
                for ev in evs.drain(..) {
                    match ev {
                        Event::Usage(u) => usage.merge(&u),
                        Event::Error { status, message } => error = Some((status, message)),
                        e if is_content(&e) => tracker.first_token(),
                        _ => {}
                    }
                }
                let data = if unwrap {
                    serde_json::from_str::<Value>(&sse.data)
                        .map(|v| crate::antigravity::unwrap(v).to_string())
                        .unwrap_or(sse.data)
                } else {
                    sse.data
                };
                yield Frame { event: sse.event.map(std::borrow::Cow::Owned), data };
            }
            if end {
                break;
            }
        }
        match error {
            Some((s, m)) => tracker.finish(s, &usage, Some(m)),
            None => tracker.finish(200, &usage, None),
        }
    })
}

/// Non-streaming client on a stream-only upstream (Codex): return the final response object.
type ByteStream = Pin<Box<dyn Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>;

async fn collect_passthrough(mut body: ByteStream, native: Format, mut tracker: Tracker, format: Format) -> Reply {
    let mut dec = SseDecoder::default();
    let mut parser = formats::parser(native);
    let mut agg = Aggregate::default();
    let mut final_obj: Option<Value> = None;
    let mut evs = Vec::new();
    let mut handle = |sse: crate::sse::SseEvent, agg: &mut Aggregate, final_obj: &mut Option<Value>| {
        parser.feed(&sse, &mut evs);
        evs.drain(..).for_each(|e| agg.push(&e));
        if let Ok(v) = serde_json::from_str::<Value>(&sse.data)
            && matches!(v["type"].as_str(), Some("response.completed") | Some("response.incomplete"))
        {
            *final_obj = Some(v["response"].clone());
        }
    };
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(c) => dec.push(&c).into_iter().for_each(|s| handle(s, &mut agg, &mut final_obj)),
            Err(e) => {
                agg.error = Some((502, format!("upstream stream error: {e}")));
                break;
            }
        }
    }
    dec.finish().into_iter().for_each(|s| handle(s, &mut agg, &mut final_obj));
    if let Some((status, msg)) = agg.error.clone() {
        tracker.finish(status, &agg.usage, Some(msg.clone()));
        return error_reply(format, status, &msg);
    }
    tracker.finish(200, &agg.usage, None);
    match final_obj {
        Some(mut obj) => {
            // Codex omits streamed output from the final event; fill it in.
            if obj["output"].as_array().is_none_or(|a| a.is_empty()) {
                let req = Request::default();
                let rebuilt = formats::responses::render_full(&agg, obj["model"].as_str().unwrap_or_default(), &req);
                obj["output"] = rebuilt["output"].clone();
            }
            Reply::Json(obj)
        }
        None => error_reply(format, 502, "upstream ended without a response"),
    }
}

// ------------------------------------------------------------------ utilities

/// `/v1/messages/count_tokens`: ask Claude when possible, otherwise estimate.
pub async fn count_tokens(app: Arc<App>, headers: HeaderMap, body: Value) -> Value {
    let cfg = app.cfg();
    let (model, _) = ir::split_model_suffix(body["model"].as_str().unwrap_or_default());
    if let Pick::Ok(acct, upstream_model) = app.pool.pick(&model, &[], cfg.routing, None, None)
        && acct.provider == Provider::Claude
        && crate::oauth::ensure_fresh(&app, &acct, Duration::minutes(5), false).await.is_ok()
    {
        let p = upstream::prepare(
            &Target {
                acct: &acct,
                cfg: &cfg,
                client_headers: &headers,
                model: &upstream_model,
                wire: Format::Claude,
                passthrough: true,
                stream: false,
                count_tokens: true,
            },
            body.clone(),
        );
        let mut rb = app.http.client(acct.proxy_url.as_deref()).post(&p.url);
        for (k, v) in &p.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if let Ok(resp) = rb.json(&p.body).send().await
            && resp.status().is_success()
            && let Ok(v) = resp.json::<Value>().await
        {
            return v;
        }
    }
    json!({ "input_tokens": estimate_tokens(&body) })
}

pub fn estimate_tokens(body: &Value) -> u64 {
    let mut chars = 0usize;
    for k in ["system", "messages", "tools", "contents", "input", "instructions"] {
        if !body[k].is_null() {
            chars += body[k].to_string().len();
        }
    }
    (chars as u64 / 4).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_failures_retry_and_quota_does_not() {
        let h = reqwest::header::HeaderMap::new();
        let busy = r#"{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}"#;
        assert!(soft_failure(Provider::Antigravity, 429, &h, busy).is_some());
        assert!(soft_failure(Provider::Claude, 429, &h, busy).is_none());
        let quota = r#"{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"reason":"QUOTA_EXHAUSTED"}]}}"#;
        assert!(soft_failure(Provider::Antigravity, 429, &h, quota).is_none());
        assert!(soft_failure(Provider::Antigravity, 503, &h, "No capacity available").is_some());
        let mut later = reqwest::header::HeaderMap::new();
        later.insert("retry-after", "3600".parse().unwrap());
        assert!(soft_failure(Provider::Codex, 429, &later, "{}").is_none());
        let mut soon = reqwest::header::HeaderMap::new();
        soon.insert("retry-after", "2".parse().unwrap());
        assert!(soft_failure(Provider::Codex, 429, &soon, "{}").is_some());
        assert!(soft_failure(Provider::Codex, 400, &h, "{}").is_none());
    }
}
