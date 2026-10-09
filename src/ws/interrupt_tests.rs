use super::tests::{account, admission_app, admission_socket};
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;

// Both sides are real loopback WebSockets; there are no model or OAuth calls.
async fn client_socket() -> (Client, Upstream, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/responses", listener.local_addr().unwrap());
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let sender = Arc::new(parking_lot::Mutex::new(Some(sender)));
    let router = axum::Router::new().route(
        "/responses",
        axum::routing::get(move |upgrade: axum::extract::ws::WebSocketUpgrade| {
            let sender = sender.clone();
            async move {
                upgrade.on_upgrade(move |socket| async move {
                    let _ = sender.lock().take().unwrap().send(socket);
                })
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let peer = tokio_tungstenite::connect_async(url).await.unwrap().0;
    let (tx, rx) = receiver.await.unwrap().split();
    (Client { tx, rx, pending: None }, peer, server)
}

async fn receive<S: AsyncRead + AsyncWrite + Unpin>(peer: &mut WebSocketStream<S>) -> Value {
    let frame = tokio::time::timeout(Duration::from_secs(5), peer.next())
        .await
        .expect("mock response/control was not delivered")
        .unwrap()
        .unwrap();
    match frame {
        tungstenite::Message::Text(text) => serde_json::from_str(&text).unwrap(),
        other => panic!("unexpected mock frame: {other:?}"),
    }
}

async fn transmit<S: AsyncRead + AsyncWrite + Unpin>(peer: &mut WebSocketStream<S>, event: &Value) {
    peer.send(tungstenite::Message::Text(event.to_string().into())).await.unwrap();
}

async fn finished<T>(task: JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), task).await.expect("relay did not finish").unwrap()
}

fn tracked(app: &Arc<App>, acct: &Arc<Account>, up: Upstream, request_id: u64) -> NativeResponse {
    let mut tracker = Tracker::new_with_id(app, Format::Responses, true, "upstream_ws", "mock-model", request_id);
    tracker.attempt(acct);
    NativeResponse { acct: acct.clone(), up, tracker, model: "mock-model".into() }
}

fn interrupt(id: &str) -> Value {
    json!({"type":"response.interrupt", "response_id":id, "mode":"discard_partial_items"})
}

#[tokio::test]
async fn interrupt_precedes_terminal_preserves_next_create_socket_and_opaque_history() {
    let (app, directory) = admission_app();
    let mut cfg = (*app.cfg()).clone();
    cfg.request_log = true;
    cfg.request_log_dir = directory.join("audit").to_string_lossy().into();
    app.set_config(cfg);
    let (mut up, mut backend) = admission_socket().await;
    let (mut client, mut peer, server) = client_socket().await;
    let acct = account();
    let mut sess = Session { pinned: Some(acct.id.clone()), ..Default::default() };
    let input = json!({"type":"message", "role":"user", "content":"synthetic input"});
    let body = json!({"model":"mock-model", "input":[input]});
    let full = input_items(&body);
    let initial = prepare_native_body(&sess, &body, &full, "mock-model", true, None).unwrap();
    transmit(&mut up, &initial).await;
    let reasoning = json!({"type":"reasoning", "id":"rs_mock", "status":"completed",
        "encrypted_content":"opaque-mock-replay", "extra_replay_field":{"preserve":true}});
    let partial = json!({"type":"message", "id":"msg_mock", "status":"incomplete", "content":[]});
    let mut control = interrupt("resp_active");
    control["extra_control_field"] = json!({"preserve":true});
    let expected_control = control.clone();
    let streamed_reasoning = reasoning.clone();
    let tool = json!({"type":"function_call", "status":"completed", "call_id":"call_mock", "name":"mock_tool", "arguments":"{}"});
    let streamed_tool = tool.clone();
    let next_body = json!({"type":"response.create", "model":"mock-model", "previous_response_id":"resp_active",
        "input":[{"type":"function_call_output", "call_id":"call_mock", "output":"synthetic tool output"}]});
    let expected_next = next_body.clone();
    let backend_task = tokio::spawn(async move {
        assert_eq!(receive(&mut backend).await, initial);
        transmit(&mut backend, &json!({"type":"response.created", "response":{"id":"resp_active"}})).await;
        transmit(
            &mut backend,
            &json!({"type":"response.output_item.done", "output_index":0, "item":streamed_reasoning}),
        )
        .await;
        transmit(&mut backend, &json!({"type":"response.output_item.done", "output_index":1, "item":streamed_tool}))
            .await;
        transmit(&mut backend, &json!({"type":"response.output_item.done", "output_index":2, "item":partial})).await;
        // Completion is causally blocked on the interrupt, so a read-starved relay fails.
        assert_eq!(receive(&mut backend).await, expected_control);
        let terminal = json!({"type":"response.incomplete", "response":{
            "id":"resp_active", "status":"incomplete", "incomplete_details":{"reason":"interrupted"},
            "output":[], "usage":{"input_tokens":100,"output_tokens":8,
                "input_tokens_details":{"cached_tokens":40}, "output_tokens_details":{"reasoning_tokens":3}}}});
        transmit(&mut backend, &terminal).await;
        let next = receive(&mut backend).await;
        assert_eq!(next["type"], "response.create");
        assert_eq!(next["previous_response_id"], "resp_active");
        assert_eq!(next["input"], expected_next["input"]);
        transmit(&mut backend, &json!({"type":"response.created", "response":{"id":"resp_next"}})).await;
        transmit(
            &mut backend,
            &json!({"type":"response.output_item.done", "output_index":0,
            "item":{"type":"reasoning","encrypted_content":"second-opaque","status":"completed"}}),
        )
        .await;
        // The old interrupt sent during the next turn must not reach this socket.
        assert_eq!(receive(&mut backend).await, interrupt("resp_next"));
        transmit(
            &mut backend,
            &json!({"type":"response.completed", "response":{
            "id":"resp_next", "status":"completed", "output":[],
            "usage":{"input_tokens":24,"output_tokens":4,"input_tokens_details":{"cached_tokens":6}}}}),
        )
        .await;
        terminal
    });
    let response = tracked(&app, &acct, up, app.stats.next_id());
    let relay_app = app.clone();
    let relay_body = body.clone();
    let relay_full = full.clone();
    let first = tokio::spawn(async move {
        let result =
            relay_native_response(&relay_app, &mut sess, &relay_body, &relay_full, &mut client, response).await;
        (result, sess, client)
    });
    assert_eq!(receive(&mut peer).await["type"], "response.created");
    assert_eq!(receive(&mut peer).await["type"], "response.output_item.done");
    assert_eq!(receive(&mut peer).await["type"], "response.output_item.done");
    assert_eq!(receive(&mut peer).await["type"], "response.output_item.done");
    transmit(&mut peer, &next_body).await;
    transmit(&mut peer, &control).await;
    let downstream_terminal = receive(&mut peer).await;
    assert_eq!(downstream_terminal["type"], "response.incomplete");
    let (result, mut sess, mut client) = finished(first).await;
    assert!(matches!(result, Native::Done));
    assert_eq!(sess.pinned.as_deref(), Some(acct.id.as_str()));
    assert_eq!(sess.lookup("resp_active").unwrap(), vec![input, reasoning, tool]);
    assert_eq!(sess.upstream_ids, VecDeque::from(["resp_active".to_string()]));
    let create = client.pending.take().expect("next create was lost");
    assert_eq!(create.body["input"], next_body["input"]);
    let mut next_full = sess.lookup("resp_active").unwrap();
    next_full.extend(input_items(&create.body));
    let next_payload = prepare_native_body(&sess, &create.body, &next_full, "mock-model", false, None).unwrap();
    let replay = prepare_native_body(&sess, &create.body, &next_full, "mock-model", true, None).unwrap();
    assert_eq!(replay["input"][1]["encrypted_content"], "opaque-mock-replay");
    assert_eq!(replay["input"][1]["extra_replay_field"], json!({"preserve":true}));
    assert_eq!(replay["input"][2]["call_id"], "call_mock");
    assert_eq!(replay["input"][3]["type"], "function_call_output");
    assert_eq!(replay["input"][3]["call_id"], "call_mock");
    let (retained_acct, mut retained_up) = sess.upstream.take().unwrap();
    assert!(Arc::ptr_eq(&retained_acct, &acct));
    transmit(&mut retained_up, &next_payload).await;
    let response = tracked(&app, &retained_acct, retained_up, create.request_id);
    let relay_app = app.clone();
    let second = tokio::spawn(async move {
        let result =
            relay_native_response(&relay_app, &mut sess, &create.body, &next_full, &mut client, response).await;
        (result, sess, client)
    });
    assert_eq!(receive(&mut peer).await["response"]["id"], "resp_next");
    assert_eq!(receive(&mut peer).await["type"], "response.output_item.done");
    transmit(&mut peer, &interrupt("resp_active")).await;
    transmit(&mut peer, &interrupt("resp_next")).await;
    assert_eq!(receive(&mut peer).await["type"], "response.completed");
    let (result, sess, client) = finished(second).await;
    assert!(matches!(result, Native::Done));
    assert_eq!(sess.lookup("resp_next").unwrap().last().unwrap()["encrypted_content"], "second-opaque");
    assert_eq!(downstream_terminal, finished(backend_task).await);
    let logs: Vec<_> = app.stats.recent.lock().iter().cloned().collect();
    assert_eq!(logs.len(), 2, "controls must not fabricate model requests");
    assert_eq!(logs[0].status, 499);
    assert_eq!(logs[0].termination_reason, Some(crate::state::TerminationReason::ResponseInterrupted));
    assert_eq!((logs[0].input_tokens, logs[0].output_tokens, logs[0].cache_tokens), (60, 8, 40));
    assert_eq!(logs[0].attempts, 1);
    assert_eq!(logs[1].status, 200, "a normal completion wins its interrupt race");
    assert_eq!(logs[1].termination_reason, None);
    let totals = app.stats.totals.lock().clone();
    assert_eq!((totals.requests, totals.ok, totals.interrupted, totals.failed), (2, 1, 1, 0));
    assert_eq!((totals.unfinished, totals.downstream_write_failed), (0, 0));
    assert_eq!(totals.response_interrupted, 1);
    assert_eq!(serde_json::to_value(&totals).unwrap()["response_interrupted"], 1);
    let bucket = app.stats.series.lock().back().unwrap().clone();
    assert_eq!(
        (bucket.interrupted, bucket.response_interrupted, bucket.unfinished, bucket.downstream_write_failed),
        (1, 1, 0, 0)
    );
    assert_eq!(serde_json::to_value(&logs[0]).unwrap()["termination_reason"], "response_interrupted");
    assert_eq!((totals.input_tokens, totals.output_tokens, totals.cache_tokens), (78, 12, 46));
    assert_eq!(app.stats.active.load(Ordering::Relaxed), 0);
    let counters = acct.state.lock().counters.clone();
    // Account failures retain the existing status>=400 accounting semantics.
    assert_eq!((counters.requests, counters.failures), (2, 1));
    drop((client, sess, peer));
    server.abort();
    let archive_app = app.clone();
    tokio::task::spawn_blocking(move || archive_app.audit.shutdown()).await.unwrap().unwrap();
    drop(app);
    let archive = std::fs::read_dir(directory.join("audit")).unwrap().next().unwrap().unwrap().path();
    let records: Vec<Value> =
        std::fs::read_to_string(archive).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let controls: Vec<_> = records.iter().filter(|record| record["direction"] == "upstream_control").collect();
    assert_eq!(controls.len(), 2);
    assert_eq!(controls[0]["data"], control);
    assert!(records.iter().any(|record| record["direction"] == "downstream_request"
        && record["request_id"] == controls[0]["request_id"]
        && record["data"] == control));
    assert!(
        !records
            .iter()
            .any(|record| record["direction"] == "summary" && record["request_id"] == controls[0]["request_id"])
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn interrupted_empty_terminal_preserves_completed_opaque_items_and_discards_partial_snapshots() {
    let complete = json!({"type":"reasoning", "status":"completed", "encrypted_content":"mock-opaque"});
    let partial = json!({"type":"message", "status":"incomplete", "content":[]});
    let mut output = TurnOutput::default();
    output.observe(&json!({"type":"response.output_item.done", "output_index":0,"item":complete}), None);
    output.observe(&json!({"type":"response.output_item.done", "output_index":1,"item":partial}), None);
    assert_eq!(
        output.captured_items(&json!({"output":[], "incomplete_details":{"reason":"interrupted"}})),
        vec![complete.clone()]
    );
    assert_eq!(output.captured_items(&json!({"output":[]})), vec![complete.clone(), partial]);
    assert_eq!(output.captured_items(&json!({"incomplete_details":{"reason":"interrupted"}})), vec![complete.clone()]);
    assert_eq!(
        output.captured_items(&json!({"output":[complete], "incomplete_details":{"reason":"interrupted"}})),
        vec![complete]
    );
}

#[tokio::test]
async fn completed_response_wins_before_late_interrupt_and_next_idle_create_survives() {
    let (app, directory) = admission_app();
    let (up, mut backend) = admission_socket().await;
    let (mut client, mut peer, server) = client_socket().await;
    let acct = account();
    let mut sess = Session::default();
    let response = tracked(&app, &acct, up, app.stats.next_id());
    let relay_app = app.clone();
    let relay = tokio::spawn(async move {
        let result =
            relay_native_response(&relay_app, &mut sess, &json!({"model":"mock-model"}), &[], &mut client, response)
                .await;
        (result, sess, client)
    });
    transmit(&mut backend, &json!({"type":"response.created","response":{"id":"completed"}})).await;
    transmit(&mut backend, &json!({"type":"response.completed","response":{"id":"completed","output":[],"usage":{"input_tokens":10,"output_tokens":2}}})).await;
    assert_eq!(receive(&mut peer).await["type"], "response.created");
    assert_eq!(receive(&mut peer).await["type"], "response.completed");
    let (result, mut sess, mut client) = finished(relay).await;
    assert!(matches!(result, Native::Done));
    transmit(&mut peer, &interrupt("completed")).await;
    transmit(
        &mut peer,
        &json!({"type":"response.create","model":"mock-model","previous_response_id":"completed","input":"next"}),
    )
    .await;
    let frame = client_frame(&app, client.rx.next().await);
    assert!(matches!(idle_input(&sess, frame), ClientFrame::Ignore));
    let frame = client_frame(&app, client.rx.next().await);
    let ClientFrame::Create(create) = idle_input(&sess, frame) else { panic!("next create was lost") };
    let payload =
        prepare_native_body(&sess, &create.body, &input_items(&create.body), "mock-model", false, None).unwrap();
    let (_, up) = sess.upstream.as_mut().unwrap();
    transmit(up, &payload).await;
    assert_eq!(receive(&mut backend).await["type"], "response.create", "late control must not be sent upstream");
    let logs = app.stats.recent.lock();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].status, 200);
    assert_eq!(logs[0].output_tokens, 2);
    drop(logs);
    drop((client, sess, backend, peer, app));
    server.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn malformed_and_unrelated_controls_are_rejected_and_completed_idle_control_is_ignored() {
    let (app, directory) = admission_app();
    for body in [
        Value::Null,
        json!([]),
        json!({"type":"response.interrupt"}),
        json!({"type":"response.interrupt","response_id":"","mode":"discard_partial_items"}),
        json!({"type":"response.interrupt","response_id":"r","mode":"other"}),
        json!({"type":"response.interrupt","response_id":12,"mode":"discard_partial_items"}),
    ] {
        let frame = client_frame(&app, Some(Ok(Message::Text(body.to_string().into()))));
        assert!(matches!(frame, ClientFrame::Invalid { .. }));
    }
    let mut sess = Session::default();
    sess.remember("completed".into(), vec![]);
    assert!(matches!(
        idle_input(&sess, client_frame(&app, Some(Ok(Message::Text(interrupt("completed").to_string().into()))))),
        ClientFrame::Ignore
    ));
    assert!(matches!(
        idle_input(&sess, client_frame(&app, Some(Ok(Message::Text(interrupt("unknown").to_string().into()))))),
        ClientFrame::Invalid { .. }
    ));
    drop(app);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn active_controls_validate_target_deduplicate_and_bound_queued_creates() {
    let (app, directory) = admission_app();
    let (up, mut backend) = admission_socket().await;
    let (mut client, mut peer, server) = client_socket().await;
    let acct = account();
    let mut sess = Session::default();
    let response = tracked(&app, &acct, up, app.stats.next_id());
    let relay_app = app.clone();
    let relay = tokio::spawn(async move {
        let result =
            relay_native_response(&relay_app, &mut sess, &json!({"model":"mock-model"}), &[], &mut client, response)
                .await;
        (result, sess, client)
    });
    transmit(&mut backend, &json!({"type":"response.created", "response":{"id":"active"}})).await;
    assert_eq!(receive(&mut peer).await["type"], "response.created");
    transmit(&mut peer, &interrupt("unknown")).await;
    assert_eq!(receive(&mut peer).await["status"], 400);
    transmit(&mut peer, &json!({"type":"response.interrupt", "response_id":"active", "mode":"wrong"})).await;
    assert_eq!(receive(&mut peer).await["status"], 400);
    let first_create = json!({"type":"response.create", "model":"mock-model", "input":"first"});
    transmit(&mut peer, &first_create).await;
    transmit(&mut peer, &json!({"type":"response.create", "model":"mock-model", "input":"second"})).await;
    assert!(receive(&mut peer).await["error"]["message"].as_str().unwrap().contains("already queued"));
    transmit(&mut peer, &interrupt("active")).await;
    transmit(&mut peer, &interrupt("active")).await;
    // This error is a barrier proving the preceding duplicate was processed.
    transmit(&mut peer, &interrupt("unknown-again")).await;
    assert_eq!(receive(&mut peer).await["status"], 400);
    assert_eq!(receive(&mut backend).await, interrupt("active"));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), backend.next()).await.is_err(),
        "invalid/duplicate controls reached upstream"
    );
    transmit(&mut backend, &json!({"type":"response.incomplete", "response":{"id":"active", "output":[], "incomplete_details":{"reason":"interrupted"},"usage":{"input_tokens":3,"output_tokens":1}}})).await;
    assert_eq!(receive(&mut peer).await["type"], "response.incomplete");
    let (result, sess, client) = finished(relay).await;
    assert!(matches!(result, Native::Done));
    assert_eq!(client.pending.as_ref().unwrap().body["input"], "first");
    assert_eq!(app.stats.recent.lock().len(), 1);
    drop((client, sess, backend, peer, app));
    server.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn downstream_close_ends_a_silent_upstream_response_promptly() {
    let (app, directory) = admission_app();
    let (up, backend) = admission_socket().await;
    let (mut client, mut peer, server) = client_socket().await;
    let acct = account();
    let mut sess = Session::default();
    sess.remember_upstream("prior".into());
    let response = tracked(&app, &acct, up, app.stats.next_id());
    let relay_app = app.clone();
    let relay = tokio::spawn(async move {
        let result =
            relay_native_response(&relay_app, &mut sess, &json!({"model":"mock-model"}), &[], &mut client, response)
                .await;
        (result, sess)
    });
    peer.close(None).await.unwrap();
    let (result, sess) = finished(relay).await;
    assert!(matches!(result, Native::Gone));
    assert!(sess.upstream_ids.is_empty());
    assert!(sess.upstream.is_none());
    assert_eq!(app.stats.active.load(Ordering::Relaxed), 0);
    assert_eq!(app.stats.recent.lock()[0].status, 499);
    drop((sess, backend, peer, app));
    server.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

struct StreamDropped(Arc<AtomicBool>);
impl Drop for StreamDropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn http_interrupt_closes_body_with_explicit_error_and_never_fabricates_completion() {
    let (app, directory) = admission_app();
    let (mut client, mut peer, server) = client_socket().await;
    let dropped = Arc::new(AtomicBool::new(false));
    let signal = dropped.clone();
    let frames: proxy::FrameStream = Box::pin(async_stream::stream! {
        let _drop = StreamDropped(signal);
        yield crate::formats::Frame::data(json!({"type":"response.created", "response":{"id":"http-active"}}).to_string());
        std::future::pending::<()>().await;
    });
    let relay_app = app.clone();
    let relay = tokio::spawn(async move {
        let mut sess = Session::default();
        let result = relay_http_response(&relay_app, 1, &mut sess, &[], &mut client, frames).await;
        (result.is_ok(), sess, client)
    });
    assert_eq!(receive(&mut peer).await["type"], "response.created");
    transmit(&mut peer, &interrupt("http-active")).await;
    let error = receive(&mut peer).await;
    assert_eq!(error["type"], "error");
    assert_eq!(error["error"]["code"], "response_interrupt_unsupported");
    let (ok, sess, client) = finished(relay).await;
    assert!(ok);
    assert!(dropped.load(Ordering::SeqCst));
    assert!(sess.history.is_empty(), "unacknowledged HTTP partial output cannot become replay history");
    assert!(app.stats.recent.lock().is_empty(), "a control must not start inference");
    drop((client, sess, peer, app));
    server.abort();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn http_terminal_wins_late_interrupt_while_body_waits_for_eof() {
    let (app, directory) = admission_app();
    let (mut client, mut peer, server) = client_socket().await;
    let (end, eof) = tokio::sync::oneshot::channel();
    let frames: proxy::FrameStream = Box::pin(async_stream::stream! {
        yield crate::formats::Frame::data(json!({"type":"response.created", "response":{"id":"http-completed"}}).to_string());
        yield crate::formats::Frame::data(json!({"type":"response.completed", "response":{"id":"http-completed","output":[]}}).to_string());
        let _ = eof.await;
    });
    let relay_app = app.clone();
    let relay = tokio::spawn(async move {
        let mut sess = Session::default();
        let result = relay_http_response(&relay_app, 1, &mut sess, &[], &mut client, frames).await;
        (result.is_ok(), sess, client)
    });
    assert_eq!(receive(&mut peer).await["type"], "response.created");
    assert_eq!(receive(&mut peer).await["type"], "response.completed");
    transmit(&mut peer, &interrupt("http-completed")).await;
    // The next validation error is a barrier proving the late control was ignored.
    transmit(&mut peer, &interrupt("unknown")).await;
    let error = receive(&mut peer).await;
    assert_eq!(error["status"], 400);
    assert!(error["error"]["code"].is_null());
    end.send(()).unwrap();
    let (ok, sess, client) = finished(relay).await;
    assert!(ok);
    assert!(sess.contains("http-completed"));
    drop((client, sess, peer, app));
    server.abort();
    std::fs::remove_dir_all(directory).unwrap();
}
