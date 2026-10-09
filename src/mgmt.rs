//! Management API used by the dashboard, plus OAuth login orchestration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use axum::Json;
use axum::Router;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::accounts::{Credential, Provider, set_file_disabled, write_oauth_file};
use crate::config::{Config, ModelAlias};
use crate::oauth;
use crate::state::App;

#[derive(Clone, Serialize)]
pub struct Login {
    pub provider: Provider,
    pub status: &'static str,
    pub message: Option<String>,
    pub url: String,
    pub callback: bool,
    /// "redirect" (browser OAuth) or "device" (enter `user_code` at `url`).
    pub kind: &'static str,
    pub user_code: Option<String>,
    #[serde(skip)]
    pub verifier: String,
    #[serde(skip)]
    pub created: Instant,
}

static CLAUDE_CB: AtomicBool = AtomicBool::new(false);
static CODEX_CB: AtomicBool = AtomicBool::new(false);
static ANTIGRAVITY_CB: AtomicBool = AtomicBool::new(false);

fn remember(app: &Arc<App>, state: &str, login: &Login) {
    let mut logins = app.logins.lock();
    logins.retain(|_, l| l.created.elapsed() < Duration::from_secs(1800));
    logins.insert(state.to_string(), login.clone());
}

fn settle(app: &Arc<App>, state: &str, result: &Result<String>) {
    if let Some(l) = app.logins.lock().get_mut(state) {
        match result {
            Ok(label) => {
                l.status = "done";
                l.message = Some(label.clone());
            }
            Err(e) => {
                l.status = "error";
                l.message = Some(format!("{e:#}"));
            }
        }
    }
    app.broadcast("login", json!({ "state": state }));
}

pub async fn start_login(app: &Arc<App>, provider: Provider) -> Result<(String, Login)> {
    let state = oauth::random_state();
    match provider {
        Provider::Claude | Provider::Codex | Provider::Antigravity => {
            let pkce = oauth::pkce();
            let url = oauth::auth_url(provider, &state, &pkce);
            let callback = ensure_callback_server(app, provider).await;
            let login = Login {
                provider,
                status: "pending",
                message: None,
                url,
                callback,
                kind: "redirect",
                user_code: None,
                verifier: pkce.verifier,
                created: Instant::now(),
            };
            remember(app, &state, &login);
            Ok((state, login))
        }
        Provider::Kimi | Provider::Xai | Provider::Meta => {
            let dev = crate::device::start(app, provider).await?;
            let login = Login {
                provider,
                status: "pending",
                message: None,
                url: dev.verification_uri.clone(),
                callback: true,
                kind: "device",
                user_code: Some(dev.user_code.clone()),
                verifier: String::new(),
                created: Instant::now(),
            };
            remember(app, &state, &login);
            let (app2, state2) = (app.clone(), state.clone());
            tokio::spawn(async move {
                let result = async {
                    let signed = crate::device::wait(&app2, provider, &dev).await?;
                    save_signed(&app2, provider, signed)
                }
                .await;
                settle(&app2, &state2, &result);
            });
            Ok((state, login))
        }
        Provider::Devin => {
            // Devin accepts any localhost redirect, so use a fresh port per login.
            let pkce = oauth::pkce();
            let (callback, redirect) = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
                Ok(listener) => {
                    let port = listener.local_addr()?.port();
                    serve_callback(app, listener, "/callback", provider, None);
                    (true, format!("http://127.0.0.1:{port}/callback"))
                }
                Err(_) => (false, String::new()),
            };
            let login = Login {
                provider,
                status: "pending",
                message: None,
                url: crate::devin::auth_url(&redirect, &state, &pkce.challenge),
                callback,
                kind: "redirect",
                user_code: None,
                verifier: pkce.verifier,
                created: Instant::now(),
            };
            remember(app, &state, &login);
            Ok((state, login))
        }
        Provider::Vertex => Err(anyhow!("Vertex uses a service account key: import the JSON instead")),
        Provider::Gemini | Provider::Compat => Err(anyhow!("{} uses API keys", provider.as_str())),
    }
}

fn save_signed(app: &Arc<App>, provider: Provider, s: crate::device::Signed) -> Result<String> {
    let path = app.cfg().auth_dir().join(&s.file);
    write_oauth_file(&path, provider, &s.oauth, &s.extra)?;
    app.reload_accounts();
    Ok(s.oauth.email.unwrap_or(s.file))
}

/// Listens on the fixed OAuth redirect port while logins are pending.
async fn ensure_callback_server(app: &Arc<App>, provider: Provider) -> bool {
    let (flag, port, path) = match provider {
        Provider::Claude => (&CLAUDE_CB, oauth::claude::PORT, "/callback"),
        Provider::Antigravity => (&ANTIGRAVITY_CB, crate::antigravity::PORT, "/oauth-callback"),
        _ => (&CODEX_CB, oauth::codex::PORT, "/auth/callback"),
    };
    if flag.load(Ordering::SeqCst) {
        return true;
    }
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                "cannot listen on localhost:{port} for the OAuth callback ({e}); paste the redirect URL instead"
            );
            return false;
        }
    };
    flag.store(true, Ordering::SeqCst);
    serve_callback(app, listener, path, provider, Some(flag));
    true
}

/// Serves the OAuth redirect on `listener` until no login for `provider` is pending.
fn serve_callback(
    app: &Arc<App>,
    listener: tokio::net::TcpListener,
    path: &'static str,
    provider: Provider,
    flag: Option<&'static AtomicBool>,
) {
    let router = Router::new().route(path, get(callback)).with_state(app.clone());
    let app2 = app.clone();
    tokio::spawn(async move {
        let shutdown = async move {
            // Stay up while a login for this provider is pending (max 15 minutes).
            let started = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let pending = app2.logins.lock().values().any(|l| l.provider == provider && l.status == "pending");
                if !pending || started.elapsed() > Duration::from_secs(900) {
                    break;
                }
            }
        };
        let _ = axum::serve(listener, router).with_graceful_shutdown(shutdown).await;
        if let Some(f) = flag {
            f.store(false, Ordering::SeqCst);
        }
    });
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(State(app): State<Arc<App>>, Query(q): Query<CallbackQuery>) -> Html<String> {
    let result = match (q.code, q.state, q.error) {
        (_, _, Some(e)) => Err(q.error_description.unwrap_or(e)),
        (Some(code), Some(state), _) => complete_login(&app, &state, &code).await.map_err(|e| format!("{e:#}")),
        _ => Err("missing code or state".to_string()),
    };
    let (title, body) = match result {
        Ok(label) => ("Signed in", format!("Connected <b>{}</b>. You can close this tab.", html_escape(&label))),
        Err(e) => ("Sign-in failed", html_escape(&e)),
    };
    Html(format!(
        r#"<!doctype html><meta charset="utf-8"><meta name="color-scheme" content="dark"><title>{title}</title>
<body style="margin:0;height:100vh;display:grid;place-items:center;background:#000;color:#f5f5f5;font:15px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif">
<div style="text-align:center;max-width:420px;padding:24px"><div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#737373">CLIProxyAPI-Rust</div>
<h1 style="font-size:22px;font-weight:600;margin:10px 0">{title}</h1><p style="color:#a3a3a3;margin:0">{body}</p></div></body>"#
    ))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub async fn complete_login(app: &Arc<App>, state: &str, code: &str) -> Result<String> {
    let (provider, verifier) = {
        let logins = app.logins.lock();
        let l = logins.get(state).ok_or_else(|| anyhow!("unknown or expired login, start again"))?;
        if l.status != "pending" {
            return Err(anyhow!("this login was already completed"));
        }
        if l.kind == "device" {
            return Err(anyhow!("approve the code in your browser; there is nothing to paste"));
        }
        (l.provider, l.verifier.clone())
    };
    let result = async {
        if provider == Provider::Devin {
            let signed = crate::devin::complete_login(app, code.trim(), &verifier).await?;
            return save_signed(app, provider, signed);
        }
        let (cred, name, extra) = oauth::exchange(app, provider, code.trim(), state, &verifier).await?;
        let path = app.cfg().auth_dir().join(&name);
        write_oauth_file(&path, provider, &cred, &extra)?;
        app.reload_accounts();
        Ok::<_, anyhow::Error>(cred.email.unwrap_or(name))
    }
    .await;
    settle(app, state, &result);
    result
}

/// Accepts a pasted redirect URL, a `code#state` string or a bare code.
pub fn parse_pasted(input: &str) -> (String, Option<String>) {
    let input = input.trim();
    if let Some(q) = input.split_once('?').map(|(_, q)| q).filter(|q| q.contains("code=")) {
        let mut code = String::new();
        let mut state = None;
        for (k, v) in url::form_urlencoded::parse(q.split('#').next().unwrap_or(q).as_bytes()) {
            match k.as_ref() {
                "code" => code = v.into_owned(),
                "state" => state = Some(v.into_owned()),
                _ => {}
            }
        }
        return (code, state);
    }
    (input.to_string(), None)
}

// ---------------------------------------------------------------------- router

pub fn router(app: Arc<App>) -> Router<Arc<App>> {
    Router::new()
        .route("/overview", get(overview))
        .route("/accounts", get(accounts))
        .route("/accounts/{id}", delete(delete_account))
        .route("/accounts/{id}/toggle", post(toggle_account))
        .route("/accounts/{id}/refresh", post(refresh_account))
        .route("/accounts/{id}/reset", post(reset_account))
        .route("/keys", post(add_key))
        .route("/vertex", post(import_vertex))
        .route("/requests", get(requests))
        .route("/models", get(models))
        .route("/config", get(get_config).put(put_config))
        .route("/login/{target}", post(login_start).get(login_status))
        .route("/login/{target}/code", post(login_code))
        .route("/live", get(live))
        .layer(middleware::from_fn_with_state(app, auth))
}

async fn auth(
    State(app): State<Arc<App>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let cfg = app.cfg();
    let key = cfg.management_key.clone();
    if key.is_empty() {
        if addr.ip().is_loopback() {
            return next.run(req).await;
        }
        return err(
            StatusCode::FORBIDDEN,
            "the dashboard is only reachable from localhost until you set management-key",
        );
    }
    if cfg.management_allow_remote == Some(false) && !addr.ip().is_loopback() {
        return err(StatusCode::FORBIDDEN, "remote management is off (allow-remote: false)");
    }
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(String::from);
    let query = req
        .uri()
        .query()
        .and_then(|q| url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "key").map(|(_, v)| v.into_owned()));
    if bearer.or(query).is_some_and(|k| management_key_matches(&k, &key)) {
        return next.run(req).await;
    }
    err(StatusCode::UNAUTHORIZED, "management key required")
}

/// Plain keys compare in constant time; bcrypt hashes (CLIProxyAPI hashes
/// `secret-key` on first start) are verified once per key and remembered.
fn management_key_matches(provided: &str, configured: &str) -> bool {
    use sha2::{Digest, Sha256};
    static VERIFIED: parking_lot::Mutex<Vec<[u8; 32]>> = parking_lot::Mutex::new(Vec::new());
    if !["$2a$", "$2b$", "$2y$"].iter().any(|p| configured.starts_with(p)) {
        return constant_eq(provided, configured);
    }
    let id: [u8; 32] = Sha256::digest(format!("{configured}\0{provided}").as_bytes()).into();
    if VERIFIED.lock().contains(&id) {
        return true;
    }
    let ok = bcrypt::verify(provided, configured).unwrap_or(false);
    if ok {
        VERIFIED.lock().push(id);
    }
    ok
}

pub fn constant_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn ok() -> Response {
    Json(json!({ "ok": true })).into_response()
}

async fn overview(State(app): State<Arc<App>>) -> Json<Value> {
    let cfg = app.cfg();
    let accounts = app.pool.all();
    let (mut active, mut cooling, mut disabled) = (0, 0, 0);
    let mut providers = std::collections::BTreeMap::<&str, usize>::new();
    for a in &accounts {
        *providers.entry(a.provider.as_str()).or_default() += 1;
        let st = a.state.lock();
        if st.disabled {
            disabled += 1;
        } else if st.cooldowns.get("*").is_some_and(|t| *t > chrono::Utc::now()) {
            cooling += 1;
        } else {
            active += 1;
        }
    }
    let host = if cfg.host == "0.0.0.0" || cfg.host.is_empty() { "127.0.0.1".to_string() } else { cfg.host.clone() };
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": app.started.to_rfc3339(),
        "uptime_secs": (chrono::Utc::now() - app.started).num_seconds(),
        "base_url": format!("http://{host}:{}", cfg.port),
        "client_keys": cfg.api_keys,
        "routing": cfg.routing,
        "management_key": !cfg.management_key.is_empty(),
        "totals": *app.stats.totals.lock(),
        "archive": app.audit.stats(),
        "active": app.stats.active.load(Ordering::Relaxed),
        "series": app.stats.series(),
        "accounts": { "total": accounts.len(), "active": active, "cooling": cooling, "disabled": disabled, "providers": providers },
        "models": app.pool.models().len(),
        "config_path": app.cfg_path.display().to_string(),
        "auth_dir": cfg.auth_dir().display().to_string(),
    }))
}

async fn accounts(State(app): State<Arc<App>>) -> Json<Value> {
    Json(Value::Array(app.pool.all().iter().map(|a| a.snapshot()).collect()))
}

async fn requests(State(app): State<Arc<App>>) -> Json<Value> {
    let recent = app.stats.recent.lock();
    Json(serde_json::to_value(recent.iter().rev().collect::<Vec<_>>()).unwrap_or_default())
}

async fn models(State(app): State<Arc<App>>) -> Json<Value> {
    Json(Value::Array(app.pool.models().into_iter().map(|(m, p)| json!({ "id": m, "provider": p })).collect()))
}

#[derive(Deserialize)]
struct ToggleBody {
    disabled: bool,
}

async fn toggle_account(State(app): State<Arc<App>>, Path(id): Path<String>, Json(b): Json<ToggleBody>) -> Response {
    let Some(acct) = app.pool.get(&id) else { return err(StatusCode::NOT_FOUND, "unknown account") };
    if let Some(path) = &acct.path
        && let Err(e) = set_file_disabled(path, b.disabled)
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    acct.state.lock().disabled = b.disabled;
    app.broadcast("accounts", Value::Null);
    ok()
}

async fn refresh_account(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(acct) = app.pool.get(&id) else { return err(StatusCode::NOT_FOUND, "unknown account") };
    if !acct.is_oauth() {
        return err(StatusCode::BAD_REQUEST, "API keys don't need refreshing");
    }
    match oauth::ensure_fresh(&app, &acct, chrono::Duration::minutes(5), true).await {
        Ok(()) => {
            let _ = crate::quota::poll(&app, &acct).await;
            acct.state.lock().cooldowns.remove("*");
            app.broadcast("accounts", Value::Null);
            ok()
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("{e:#}")),
    }
}

async fn reset_account(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(acct) = app.pool.get(&id) else { return err(StatusCode::NOT_FOUND, "unknown account") };
    let mut st = acct.state.lock();
    st.cooldowns.clear();
    st.strikes = 0;
    st.last_error = None;
    drop(st);
    app.broadcast("accounts", Value::Null);
    ok()
}

async fn delete_account(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let Some(acct) = app.pool.get(&id) else { return err(StatusCode::NOT_FOUND, "unknown account") };
    if let Some(path) = &acct.path {
        if let Err(e) = std::fs::remove_file(path) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        app.reload_accounts();
        return ok();
    }
    let key = match &*acct.cred.read() {
        Credential::ApiKey { key, .. } => key.clone(),
        _ => String::new(),
    };
    let group = if acct.provider == Provider::Compat { acct.group.clone() } else { None };
    edit_config(&app, |doc| crate::compat::remove_key(doc, &key, group.as_deref()))
}

#[derive(Deserialize)]
struct KeyBody {
    provider: String,
    api_key: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    models: String,
}

async fn add_key(State(app): State<Arc<App>>, Json(b): Json<KeyBody>) -> Response {
    let key = b.api_key.trim().to_string();
    let base = Some(b.base_url.trim().to_string()).filter(|s| !s.is_empty());
    let models: Vec<ModelAlias> = b
        .models
        .split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|m| match m.split_once('=') {
            Some((alias, name)) => ModelAlias { name: name.trim().into(), alias: Some(alias.trim().into()) },
            None => ModelAlias { name: m.into(), alias: None },
        })
        .collect();
    let models: Vec<(String, Option<String>)> = models.into_iter().map(|m| (m.name, m.alias)).collect();
    let (group, name) = match Provider::parse(&b.provider) {
        Some(Provider::Compat) => {
            let Some(base) = &base else { return err(StatusCode::BAD_REQUEST, "base URL is required") };
            if models.is_empty() {
                return err(StatusCode::BAD_REQUEST, "list at least one model");
            }
            let name = if b.name.trim().is_empty() {
                url::Url::parse(base)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
                    .unwrap_or_else(|| "provider".into())
            } else {
                b.name.trim().to_string()
            };
            ("openai-compatibility", Some(name))
        }
        Some(
            p @ (Provider::Claude
            | Provider::Codex
            | Provider::Gemini
            | Provider::Vertex
            | Provider::Kimi
            | Provider::Xai
            | Provider::Meta),
        ) => {
            if key.is_empty() {
                return err(StatusCode::BAD_REQUEST, "API key is required");
            }
            (p.as_str(), None)
        }
        Some(p) => return err(StatusCode::BAD_REQUEST, format!("{} does not take API keys", p.as_str())),
        None => return err(StatusCode::BAD_REQUEST, "unknown provider"),
    };
    let new = crate::compat::NewKey { group, api_key: &key, base_url: base.as_deref(), models, name: name.as_deref() };
    edit_config(&app, |doc| crate::compat::add_key(doc, &new))
}

#[derive(Deserialize)]
struct VertexBody {
    json: String,
    #[serde(default)]
    location: String,
}

async fn import_vertex(State(app): State<Arc<App>>, Json(b): Json<VertexBody>) -> Response {
    match crate::vertex::import(&app, &b.json, &b.location).await {
        Ok(label) => Json(json!({ "ok": true, "label": label })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

/// Applies an edit to the config file's YAML tree, keeping every setting this
/// binary doesn't know about (so the file still works with CLIProxyAPI).
fn edit_config(app: &Arc<App>, edit: impl FnOnce(&mut serde_yaml::Value)) -> Response {
    let text = std::fs::read_to_string(&app.cfg_path).unwrap_or_default();
    let mut doc: serde_yaml::Value = match serde_yaml::from_str(&text) {
        Ok(serde_yaml::Value::Null) | Err(_) if text.trim().is_empty() => {
            serde_yaml::Value::Mapping(Default::default())
        }
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("config.yaml doesn't parse: {e}")),
    };
    edit(&mut doc);
    let out = match serde_yaml::to_string(&doc) {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let cfg = match Config::parse(&out) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    };
    let capture = match app.audit.prepare_configuration(&cfg) {
        Ok(capture) => capture,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("capture configuration rejected: {e}")),
    };
    // Rewriting drops YAML comments; keep the original once.
    let backup = app.cfg_path.with_extension("yaml.bak");
    if text.contains('#') && !backup.exists() {
        let _ = std::fs::write(&backup, &text);
    }
    if let Err(e) = std::fs::write(&app.cfg_path, out) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    if let Err(e) = app.set_prepared_config(cfg, capture) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("config not applied: {e}"));
    }
    ok()
}

async fn get_config(State(app): State<Arc<App>>) -> Json<Value> {
    let text = std::fs::read_to_string(&app.cfg_path).unwrap_or_default();
    Json(json!({ "text": text, "path": app.cfg_path.display().to_string() }))
}

#[derive(Deserialize)]
struct ConfigBody {
    text: String,
}

async fn put_config(State(app): State<Arc<App>>, Json(b): Json<ConfigBody>) -> Response {
    let cfg = match Config::parse(&b.text) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let old = app.cfg();
    let capture = match app.audit.prepare_configuration(&cfg) {
        Ok(capture) => capture,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("capture configuration rejected: {e}")),
    };
    if let Err(e) = std::fs::write(&app.cfg_path, &b.text) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let restart = cfg.host != old.host || cfg.port != old.port;
    if let Err(e) = app.set_prepared_config(cfg, capture) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("config not applied: {e}"));
    }
    Json(json!({ "ok": true, "restart_required": restart })).into_response()
}

async fn login_start(State(app): State<Arc<App>>, Path(target): Path<String>) -> Response {
    let Some(provider) = Provider::parse(&target) else { return err(StatusCode::BAD_REQUEST, "unknown provider") };
    match start_login(&app, provider).await {
        Ok((state, l)) => Json(json!({
            "state": state, "url": l.url, "callback": l.callback, "kind": l.kind, "user_code": l.user_code,
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

async fn login_status(State(app): State<Arc<App>>, Path(target): Path<String>) -> Response {
    match app.logins.lock().get(&target) {
        Some(l) => Json(serde_json::to_value(l).unwrap_or_default()).into_response(),
        None => err(StatusCode::NOT_FOUND, "unknown login"),
    }
}

#[derive(Deserialize)]
struct CodeBody {
    input: String,
}

async fn login_code(State(app): State<Arc<App>>, Path(target): Path<String>, Json(b): Json<CodeBody>) -> Response {
    let (code, state) = parse_pasted(&b.input);
    if code.is_empty() {
        return err(StatusCode::BAD_REQUEST, "no authorization code found");
    }
    if state.as_deref().is_some_and(|s| s != target) {
        return err(StatusCode::BAD_REQUEST, "that URL belongs to a different login attempt");
    }
    match complete_login(&app, &target, &code).await {
        Ok(label) => Json(json!({ "ok": true, "label": label })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

async fn live(State(app): State<Arc<App>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        let mut rx = app.live.subscribe();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Ok(m) => if socket.send(Message::Text(m.into())).await.is_err() { break },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                },
                _ = tick.tick() => {
                    let msg = json!({ "type": "tick", "data": {
                        "active": app.stats.active.load(Ordering::Relaxed),
                        "totals": *app.stats.totals.lock(),
                    }}).to_string();
                    if socket.send(Message::Text(msg.into())).await.is_err() { break }
                }
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                },
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcrypt_management_keys() {
        let hash = bcrypt::hash("open sesame", 4).unwrap();
        assert!(management_key_matches("open sesame", &hash));
        assert!(management_key_matches("open sesame", &hash));
        assert!(!management_key_matches("wrong", &hash));
        assert!(management_key_matches("plain", "plain"));
        assert!(!management_key_matches("plain", "other"));
    }

    #[tokio::test]
    async fn config_updates_validate_capture_before_replacing_the_config_file() {
        let dir = std::env::temp_dir().join(format!("cliproxy-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        let original = "request-log: false\n";
        std::fs::write(&path, original).unwrap();
        let app = App::new(Config { auth_dir: "/nonexistent".into(), ..Default::default() }, path.clone()).unwrap();
        let invalid = format!("request-log: true\nrequest-log-dir: {}\n", dir.join("unenrolled").display());
        let response = put_config(State(app.clone()), Json(ConfigBody { text: invalid })).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(!app.cfg().request_log);
        assert!(!dir.join("unenrolled").exists());
        app.audit.shutdown().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
