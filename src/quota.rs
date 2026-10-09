//! Subscription quota: how much of each usage window (Claude's 5-hour and
//! weekly limits, ChatGPT's Codex windows) an account has used. Read from
//! response headers on every request and from the providers' usage endpoints
//! in the background, so routing can prefer the account with most headroom.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::accounts::{Account, Credential, Provider};
use crate::state::App;

const CLAUDE_USAGE: &str = "https://api.anthropic.com/api/oauth/usage";
const CODEX_USAGE: &str = "https://chatgpt.com/backend-api/wham/usage";
/// Accounts without quota data count as half used.
pub const UNKNOWN: f64 = 50.0;
const POLL_EVERY: i64 = 5 * 60;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Window {
    /// "5h", "week", ...
    pub name: String,
    /// 0-100.
    pub used: f64,
    pub resets_at: Option<DateTime<Utc>>,
    /// Only counts for models whose name contains this ("opus", "sonnet").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Quota {
    pub windows: Vec<Window>,
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
}

impl Quota {
    fn live(&self, model: &str) -> impl Iterator<Item = &Window> {
        let now = Utc::now();
        let model = model.to_ascii_lowercase();
        self.windows
            .iter()
            .filter(move |w| w.model.as_ref().is_none_or(|m| model.contains(m.as_str())))
            .filter(move |w| w.resets_at.is_none_or(|r| r > now))
    }

    /// Use of the tightest window that applies to `model` (None = no data).
    pub fn pressure(&self, model: &str) -> Option<f64> {
        self.updated_at?;
        Some(self.live(model).map(|w| w.used).fold(0.0, f64::max))
    }

    /// A window that is used up, and when it resets.
    pub fn exhausted_until(&self, model: &str) -> Option<DateTime<Utc>> {
        self.live(model).filter(|w| w.used >= 100.0).filter_map(|w| w.resets_at).max()
    }

    fn set(&mut self, windows: Vec<Window>, plan: Option<String>) {
        if windows.is_empty() {
            return;
        }
        // Headers only carry the general windows; keep model-scoped ones from the last poll.
        let scoped: Vec<Window> = self
            .windows
            .iter()
            .filter(|w| w.model.is_some() && !windows.iter().any(|n| n.name == w.name))
            .cloned()
            .collect();
        self.windows = windows;
        self.windows.extend(scoped);
        self.updated_at = Some(Utc::now());
        if plan.is_some() {
            self.plan = plan;
        }
    }
}

fn label(secs: i64) -> String {
    match secs {
        s if s >= 6 * 86_400 => "week".into(),
        s if s >= 20 * 3600 => "day".into(),
        s => format!("{}h", (s + 1800) / 3600),
    }
}

fn ts(secs: i64) -> Option<DateTime<Utc>> {
    (secs > 0).then(|| DateTime::from_timestamp(secs, 0)).flatten()
}

/// Reads the quota headers a Claude or ChatGPT response carries.
pub fn observe(acct: &Account, headers: &reqwest::header::HeaderMap) {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty());
    let num = |n: &str| h(n).and_then(|v| v.parse::<f64>().ok());
    let mut windows = Vec::new();
    let mut plan = None;
    match acct.provider {
        Provider::Claude => {
            for (key, name) in [("5h", "5h"), ("7d", "week")] {
                let Some(u) = num(&format!("anthropic-ratelimit-unified-{key}-utilization")) else { continue };
                let rejected = h(&format!("anthropic-ratelimit-unified-{key}-status")) == Some("rejected");
                let reset = num(&format!("anthropic-ratelimit-unified-{key}-reset")).and_then(|t| ts(t as i64));
                let used = if rejected { 100.0 } else { (u * 100.0).clamp(0.0, 100.0) };
                windows.push(Window { name: name.into(), used, resets_at: reset, model: None });
            }
        }
        Provider::Codex => {
            for which in ["primary", "secondary"] {
                let minutes = num(&format!("x-codex-{which}-window-minutes")).unwrap_or(0.0) as i64;
                let Some(used) = num(&format!("x-codex-{which}-used-percent")).filter(|_| minutes > 0) else {
                    continue;
                };
                let reset = num(&format!("x-codex-{which}-reset-at")).and_then(|t| ts(t as i64)).or_else(|| {
                    num(&format!("x-codex-{which}-reset-after-seconds"))
                        .map(|s| Utc::now() + chrono::Duration::seconds(s as i64))
                });
                windows.push(Window {
                    name: label(minutes * 60),
                    used: used.clamp(0.0, 100.0),
                    resets_at: reset,
                    model: None,
                });
            }
            plan = h("x-codex-plan-type").map(String::from);
        }
        _ => return,
    }
    acct.state.lock().quota.set(windows, plan);
}

/// Codex websocket sessions report quota as a `codex.rate_limits` event.
pub fn observe_codex_event(acct: &Account, v: &Value) {
    if v["type"] != "codex.rate_limits" {
        return;
    }
    let rl = if v["rate_limits"].is_object() { &v["rate_limits"] } else { v };
    let windows = ["primary", "secondary"]
        .iter()
        .filter_map(|which| {
            let w = &rl[*which];
            let minutes = w["window_minutes"].as_i64().filter(|m| *m > 0)?;
            let reset = w["reset_at"]
                .as_i64()
                .and_then(ts)
                .or_else(|| w["reset_after_seconds"].as_i64().map(|s| Utc::now() + chrono::Duration::seconds(s)));
            Some(Window { name: label(minutes * 60), used: w["used_percent"].as_f64()?, resets_at: reset, model: None })
        })
        .collect();
    acct.state.lock().quota.set(windows, v["plan_type"].as_str().map(String::from));
}

fn claude_windows(v: &Value) -> Vec<Window> {
    let rfc = |s: &Value| s.as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|t| t.with_timezone(&Utc));
    [
        ("five_hour", "5h", None),
        ("seven_day", "week", None),
        ("seven_day_opus", "week opus", Some("opus")),
        ("seven_day_sonnet", "week sonnet", Some("sonnet")),
    ]
    .iter()
    .filter_map(|(key, name, model)| {
        let w = &v[*key];
        Some(Window {
            name: (*name).into(),
            used: w["utilization"].as_f64()?.clamp(0.0, 100.0),
            resets_at: rfc(&w["resets_at"]),
            model: model.map(String::from),
        })
    })
    .collect()
}

fn codex_windows(v: &Value) -> Vec<Window> {
    let rl = &v["rate_limit"];
    let reached = rl["limit_reached"] == true;
    ["primary_window", "secondary_window"]
        .iter()
        .filter_map(|key| {
            let w = &rl[*key];
            let secs = w["limit_window_seconds"].as_i64().filter(|s| *s > 0)?;
            let used = w["used_percent"].as_f64()?;
            let reset = w["reset_at"].as_i64().and_then(ts);
            let used = if reached && used >= 99.0 { 100.0 } else { used.clamp(0.0, 100.0) };
            Some(Window { name: label(secs), used, resets_at: reset, model: None })
        })
        .collect()
}

fn subscription_credentials(acct: &Account) -> Result<(String, String)> {
    ensure!(acct.provider == Provider::Codex, "subscription-only mode requires a Codex account");
    let cred = acct.cred.read();
    let Credential::OAuth(o) = &*cred else {
        bail!("subscription-only mode does not permit API keys");
    };
    ensure!(o.uses_codex_backend(), "subscription-only mode does not permit a custom upstream URL");
    ensure!(!o.access_token.trim().is_empty(), "missing Codex OAuth access token");
    let account_id =
        o.account_id.as_deref().filter(|id| !id.trim().is_empty()).context("missing ChatGPT account ID")?;
    Ok((o.access_token.clone(), account_id.to_string()))
}

async fn codex_usage(app: &App, acct: &Account, token: &str, account_id: Option<&str>) -> Result<Value> {
    let mut rb = app
        .http
        .client(acct.proxy_url.as_deref())
        .get(CODEX_USAGE)
        .bearer_auth(token)
        .header("user-agent", crate::upstream::CODEX_USER_AGENT)
        .header("originator", crate::upstream::CODEX_ORIGINATOR)
        .timeout(Duration::from_secs(15));
    if let Some(id) = account_id {
        rb = rb.header("chatgpt-account-id", id);
    }
    rb.send().await?.error_for_status()?.json().await.context("invalid ChatGPT usage response")
}

fn checked_subscription_limit(rl: &Value, name: &str, ceiling: f64, now: DateTime<Utc>) -> Result<Vec<Window>> {
    ensure!(rl["allowed"] == true, "{name} subscription allowance is unavailable");
    ensure!(rl["limit_reached"] == false, "{name} subscription allowance is exhausted or unknown");
    let mut windows = Vec::new();
    for key in ["primary_window", "secondary_window"] {
        let w = &rl[key];
        if w.is_null() {
            continue;
        }
        let secs =
            w["limit_window_seconds"].as_i64().filter(|s| *s > 0).context("invalid subscription window length")?;
        let used = w["used_percent"].as_f64().context("missing subscription usage percentage")?;
        ensure!(used.is_finite() && (0.0..=100.0).contains(&used), "invalid subscription usage percentage");
        let reset = w["reset_at"].as_i64().and_then(ts).context("missing or invalid subscription reset time")?;
        ensure!(reset > now, "subscription usage window has expired; current allowance is unknown");
        ensure!(used < ceiling, "{name} subscription usage is {used}%, at or above the {ceiling}% ceiling");
        let window = label(secs);
        windows.push(Window {
            name: if name == "Codex" { window } else { format!("{name} {window}") },
            used,
            resets_at: Some(reset),
            model: None,
        });
    }
    ensure!(!windows.is_empty(), "missing {name} subscription usage windows");
    Ok(windows)
}

fn subscription_windows(v: &Value, ceiling: f64) -> Result<Vec<Window>> {
    ensure!(ceiling.is_finite() && ceiling > 0.0 && ceiling <= 100.0, "invalid subscription usage ceiling");
    ensure!(
        matches!(v["plan_type"].as_str(), Some("plus" | "pro")),
        "subscription-only mode requires a ChatGPT Plus or Pro plan"
    );
    let now = Utc::now();
    let mut windows = checked_subscription_limit(&v["rate_limit"], "Codex", ceiling, now)?;
    if let Some(additional) = v.get("additional_rate_limits").filter(|value| !value.is_null()) {
        let limits = additional.as_array().context("invalid additional subscription limits")?;
        for limit in limits {
            // Without a verified model selector, an additional bucket applies conservatively to every model.
            let name = limit["limit_name"].as_str().unwrap_or("additional Codex");
            windows.extend(checked_subscription_limit(&limit["rate_limit"], name, ceiling, now)?);
        }
    }
    // Credits never establish eligibility. Only the subscription windows above authorize a request.
    Ok(windows)
}

/// Checks official subscription allowance before each inference, including on reused sockets.
/// A preflight cannot prevent provider-side credit charges if a request crosses the remaining allowance.
pub async fn require_subscription(app: &App, acct: &Arc<Account>, model: &str) -> Result<()> {
    let cfg = app.cfg();
    if !cfg.codex_subscription_only {
        return Ok(());
    }
    let (token, account_id) = subscription_credentials(acct)?;
    let active = app.pool.get(&acct.id).context("subscription account is no longer configured")?;
    ensure!(Arc::ptr_eq(acct, &active) && !acct.state.lock().disabled, "subscription account changed or is disabled");
    let usage =
        codex_usage(app, acct, &token, Some(&account_id)).await.context("subscription allowance check failed")?;
    let windows = subscription_windows(&usage, cfg.subscription_usage_ceiling_percent)
        .with_context(|| format!("subscription allowance rejected for {model}"))?;
    let active = app.pool.get(&acct.id).context("subscription account is no longer configured")?;
    ensure!(Arc::ptr_eq(acct, &active) && !acct.state.lock().disabled, "subscription account changed or is disabled");
    ensure!(
        subscription_credentials(acct)? == (token, account_id),
        "subscription credentials changed during the allowance check; retry the request"
    );
    acct.state.lock().quota.set(windows, usage["plan_type"].as_str().map(String::from));
    Ok(())
}

/// Asks the provider's usage endpoint (free, no tokens) for current quota.
pub async fn poll(app: &App, acct: &Arc<Account>) -> anyhow::Result<()> {
    let (token, account_id) = match &*acct.cred.read() {
        Credential::OAuth(o) if o.base_url.is_none() => (o.access_token.clone(), o.account_id.clone()),
        _ => return Ok(()),
    };
    let http = app.http.client(acct.proxy_url.as_deref());
    let (windows, plan) = match acct.provider {
        Provider::Claude => {
            let v: Value = http
                .get(CLAUDE_USAGE)
                .bearer_auth(&token)
                .header("anthropic-beta", "oauth-2025-04-20")
                .header("user-agent", crate::upstream::CC_USER_AGENT)
                .timeout(Duration::from_secs(15))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            (claude_windows(&v), None)
        }
        Provider::Codex => {
            let v = codex_usage(app, acct, &token, account_id.as_deref()).await?;
            (codex_windows(&v), v["plan_type"].as_str().map(String::from))
        }
        _ => return Ok(()),
    };
    acct.state.lock().quota.set(windows, plan);
    Ok(())
}

/// Keeps quota fresh for signed-in Claude and ChatGPT accounts.
pub async fn poller(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(2)).await;
    loop {
        let mut changed = false;
        for acct in app.pool.all() {
            // Learn an Antigravity account's real model list without waiting for a request.
            if acct.provider == Provider::Antigravity
                && acct.is_oauth()
                && acct.discovered.read().is_empty()
                && !acct.state.lock().disabled
            {
                match crate::oauth::ensure_ready(&app, &acct).await {
                    Ok(()) => changed |= !acct.discovered.read().is_empty(),
                    Err(e) => tracing::debug!(account = %acct.label, "antigravity setup failed: {e:#}"),
                }
            }
            if !matches!(acct.provider, Provider::Claude | Provider::Codex) || !acct.is_oauth() {
                continue;
            }
            let stale = {
                let st = acct.state.lock();
                !st.disabled && st.quota.updated_at.is_none_or(|t| (Utc::now() - t).num_seconds() >= POLL_EVERY)
            };
            if !stale || crate::oauth::ensure_fresh(&app, &acct, chrono::Duration::minutes(5), false).await.is_err() {
                continue;
            }
            match poll(&app, &acct).await {
                Ok(()) => changed = true,
                Err(e) => tracing::debug!(account = %acct.label, "quota check failed: {e:#}"),
            }
        }
        if changed {
            app.broadcast("accounts", Value::Null);
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subscription_usage() -> Value {
        json!({
            "plan_type": "pro",
            "rate_limit": {
                "allowed": true,
                "limit_reached": false,
                "primary_window": {
                    "used_percent": 20,
                    "limit_window_seconds": 18_000,
                    "reset_at": (Utc::now() + chrono::Duration::hours(1)).timestamp()
                },
                "secondary_window": null
            }
        })
    }

    fn account(cred: Credential) -> Account {
        Account {
            id: "test".into(),
            provider: Provider::Codex,
            label: "test".into(),
            path: None,
            group: None,
            models: vec![],
            headers: Default::default(),
            proxy_url: None,
            cred: parking_lot::RwLock::new(cred),
            state: parking_lot::Mutex::new(Default::default()),
            refresh_lock: tokio::sync::Mutex::new(()),
            device_id: String::new(),
            session_id: String::new(),
            discovered: parking_lot::RwLock::new(vec![]),
            prefix: None,
            excluded: vec![],
            aliases: vec![],
        }
    }

    #[test]
    fn subscription_requires_known_available_allowance() {
        assert!(subscription_windows(&subscription_usage(), 90.0).is_ok());
        let mut plus = subscription_usage();
        plus["plan_type"] = "plus".into();
        assert!(subscription_windows(&plus, 90.0).is_ok());
        for value in [Value::Null, json!({}), json!({ "plan_type": "pro", "rate_limit": {} })] {
            assert!(subscription_windows(&value, 90.0).is_err());
        }
        for plan in ["free", "team", "business", "enterprise", "edu", "go", "unknown", ""] {
            let mut usage = subscription_usage();
            usage["plan_type"] = plan.into();
            assert!(subscription_windows(&usage, 90.0).is_err());
        }
        for field in ["allowed", "limit_reached"] {
            let mut usage = subscription_usage();
            usage["rate_limit"].as_object_mut().unwrap().remove(field);
            assert!(subscription_windows(&usage, 90.0).is_err());
        }
        let mut usage = subscription_usage();
        usage["rate_limit"]["limit_reached"] = true.into();
        assert!(subscription_windows(&usage, 90.0).is_err());
        usage["rate_limit"]["limit_reached"] = false.into();
        usage["rate_limit"]["allowed"] = false.into();
        assert!(subscription_windows(&usage, 90.0).is_err());
    }

    #[test]
    fn subscription_blocks_at_ceiling_and_rejects_invalid_windows() {
        for (used, allowed) in [(90.0, true), (99.9, true), (100.0, false)] {
            let mut usage = subscription_usage();
            usage["rate_limit"]["primary_window"]["used_percent"] = used.into();
            assert_eq!(subscription_windows(&usage, 100.0).is_ok(), allowed);
        }
        for used in [90.0, 99.0, 100.0, -1.0, 101.0] {
            let mut usage = subscription_usage();
            usage["rate_limit"]["primary_window"]["used_percent"] = used.into();
            assert!(subscription_windows(&usage, 90.0).is_err());
        }
        let mut usage = subscription_usage();
        usage["rate_limit"]["primary_window"]["used_percent"] = 89.9.into();
        assert!(subscription_windows(&usage, 90.0).is_ok());
        usage["rate_limit"]["secondary_window"] = usage["rate_limit"]["primary_window"].clone();
        usage["rate_limit"]["secondary_window"]["used_percent"] = 90.into();
        assert!(subscription_windows(&usage, 90.0).is_err());
        usage["rate_limit"]["secondary_window"] = Value::Null;
        for reset in [Value::Null, json!(0), json!(-1), json!("tomorrow"), json!(Utc::now().timestamp() - 1)] {
            let mut usage = subscription_usage();
            usage["rate_limit"]["primary_window"]["reset_at"] = reset;
            assert!(subscription_windows(&usage, 90.0).is_err());
        }
        for field in ["used_percent", "reset_at", "limit_window_seconds"] {
            let mut usage = subscription_usage();
            usage["rate_limit"]["primary_window"].as_object_mut().unwrap().remove(field);
            assert!(subscription_windows(&usage, 90.0).is_err());
        }
        usage["rate_limit"]["primary_window"] = Value::Null;
        assert!(subscription_windows(&usage, 90.0).is_err());
        for ceiling in [0.0, -1.0, 101.0, f64::NAN, f64::INFINITY] {
            assert!(subscription_windows(&subscription_usage(), ceiling).is_err());
        }
    }

    #[test]
    fn credits_never_replace_subscription_allowance() {
        let mut usage = subscription_usage();
        usage["credits"] = json!({ "has_credits": true, "unlimited": true, "balance": "1000" });
        assert!(subscription_windows(&usage, 90.0).is_ok());
        usage["rate_limit"]["primary_window"]["used_percent"] = 100.into();
        assert!(subscription_windows(&usage, 90.0).is_err());
        usage["rate_limit"] = Value::Null;
        assert!(subscription_windows(&usage, 90.0).is_err());
    }

    #[test]
    fn additional_subscription_buckets_cannot_bypass_the_ceiling() {
        let mut usage = subscription_usage();
        let additional = json!({
            "limit_name": "GPT-5.3-Codex-Spark",
            "metered_feature": "codex_spark",
            "rate_limit": usage["rate_limit"].clone()
        });
        usage["additional_rate_limits"] = json!([additional]);
        assert_eq!(subscription_windows(&usage, 90.0).unwrap().len(), 2);
        usage["additional_rate_limits"][0]["rate_limit"]["primary_window"]["used_percent"] = 95.into();
        assert!(subscription_windows(&usage, 90.0).is_err());
        usage["additional_rate_limits"][0]["rate_limit"] = Value::Null;
        assert!(subscription_windows(&usage, 90.0).is_err());
        usage["additional_rate_limits"] = json!({ "unexpected": true });
        assert!(subscription_windows(&usage, 90.0).is_err());
    }

    #[tokio::test]
    async fn subscription_guard_rejects_api_keys_without_a_network_request() {
        let app = App::new(
            crate::config::Config {
                auth_dir: "/nonexistent".into(),
                codex_subscription_only: true,
                ..Default::default()
            },
            "unused.yaml".into(),
        );
        let acct = Arc::new(account(Credential::ApiKey { key: "synthetic-key".into(), base_url: None }));
        let error = require_subscription(&app, &acct, "gpt-6.1-sol").await.unwrap_err();
        assert!(error.to_string().contains("API keys"));
    }

    #[test]
    fn subscription_credentials_require_an_official_oauth_account() {
        let oauth = crate::accounts::OAuth {
            access_token: "synthetic-token".into(),
            account_id: Some("synthetic-account".into()),
            ..Default::default()
        };
        assert!(subscription_credentials(&account(Credential::OAuth(oauth.clone()))).is_ok());
        let custom = crate::accounts::OAuth { base_url: Some("https://example.com".into()), ..oauth.clone() };
        assert!(subscription_credentials(&account(Credential::OAuth(custom))).is_err());
        let mut other = account(Credential::OAuth(oauth.clone()));
        other.provider = Provider::Claude;
        assert!(subscription_credentials(&other).is_err());
        let no_account = crate::accounts::OAuth { account_id: None, ..oauth };
        assert!(subscription_credentials(&account(Credential::OAuth(no_account))).is_err());
    }

    #[tokio::test]
    async fn subscription_guard_is_inactive_by_default() {
        let app = App::new(
            crate::config::Config { auth_dir: "/nonexistent".into(), ..Default::default() },
            "unused.yaml".into(),
        );
        let acct = Arc::new(account(Credential::ApiKey { key: "synthetic-key".into(), base_url: None }));
        assert!(require_subscription(&app, &acct, "gpt-6.1-sol").await.is_ok());
    }

    #[test]
    fn usage_endpoints_parse() {
        let claude = json!({
            "five_hour": { "utilization": 81.0, "resets_at": "2099-10-02T12:09:59.520850+00:00" },
            "seven_day": { "utilization": 56.0, "resets_at": "2099-10-05T18:59:59+00:00" },
            "seven_day_opus": null,
        });
        let w = claude_windows(&claude);
        assert_eq!(w.len(), 2);
        assert_eq!((w[0].name.as_str(), w[0].used), ("5h", 81.0));
        assert_eq!(w[1].name, "week");

        let codex = json!({ "rate_limit": { "limit_reached": false,
            "primary_window": { "used_percent": 31, "limit_window_seconds": 604800, "reset_at": 4102444800i64 },
            "secondary_window": null } });
        let w = codex_windows(&codex);
        assert_eq!((w[0].name.as_str(), w[0].used), ("week", 31.0));
    }

    #[test]
    fn pressure_uses_the_tightest_live_window() {
        let future = Utc::now() + chrono::Duration::hours(1);
        let past = Utc::now() - chrono::Duration::hours(1);
        let mut q = Quota::default();
        assert_eq!(q.pressure("claude-opus-5-5"), None);
        q.set(
            vec![
                Window { name: "5h".into(), used: 81.0, resets_at: Some(future), model: None },
                Window { name: "week".into(), used: 56.0, resets_at: Some(future), model: None },
                Window { name: "old".into(), used: 99.0, resets_at: Some(past), model: None },
                Window { name: "week opus".into(), used: 100.0, resets_at: Some(future), model: Some("opus".into()) },
            ],
            None,
        );
        assert_eq!(q.pressure("claude-sonnet-5-5"), Some(81.0));
        assert_eq!(q.pressure("claude-opus-5-5"), Some(100.0));
        assert_eq!(q.exhausted_until("claude-opus-5-5"), Some(future));
        assert_eq!(q.exhausted_until("claude-sonnet-5-5"), None);
    }
}
