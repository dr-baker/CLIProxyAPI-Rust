# Local AI proxy

## What we're after

Maintain Daniel's own Rust proxy implementation in `dr-baker/CLIProxyAPI-Rust`. Preserve Codex subscription authentication, end-to-end WebSockets, faithful protocol handling, and durable local capture. Capture and file lifecycle changes support the sibling Codex Meta archive.

## Where to go

- `README.md`: proxy setup and configuration.
- `src/ws.rs`: downstream/upstream Responses WebSocket sessions.
- `src/proxy.rs`: routing, streaming, usage, and request termination.
- `src/audit.rs`: local captures and archive writer lifecycle.
- `../codex-meta/docs/`: combined dataset design and source-retention contracts.

## Ground rules

- Develop and publish to Daniel's fork. Upstream remains a reference; do not open upstream issues or PRs unless Daniel asks again.
- Preserve original wire events, opaque items, and genuine terminal usage. Control messages must remain responsive during generation.
- Keep subscription-only routing fail-closed. Preserve account credentials outside Git.
- Capture gaps and interrupted requests must remain distinguishable from successful requests and upstream errors.
- Source cleanup is optional. Prove producer closure and archive recovery before retiring capture files.
- Build substantial changes in copy-on-write worktrees and land with no-fast-forward merges.

## Vocabulary

- Control frame: a client WebSocket message such as `response.interrupt` that acts on an existing response.
- Producer closure: a durable guarantee that the capture writer cannot append to a retired file.
