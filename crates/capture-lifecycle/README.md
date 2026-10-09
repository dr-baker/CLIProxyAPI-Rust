# Capture lifecycle reference

`capture-lifecycle` coordinates daily JSONL producers and offline file closure. It stores metadata beside existing raw capture files. The proxy and a local OpenTelemetry collector can share this crate through path or pinned Git dependencies.

## Enrollment and producer ownership

`enroll(root, layout, initial_day)` explicitly adopts a directory. Stop and drain every legacy producer first. Older binaries ignore this protocol and its advisory lock.

`CaptureRoot::open(root, layout)` requires valid enrollment and takes an exclusive, nonblocking lock on `.capture-state/producer.lock`. Missing or malformed initialized metadata, a missing permanent lock file, mismatched layouts, and lock contention are errors. Repeated enrollment preserves the original root UUID and never lowers the capture day floor.

Keep `CaptureRoot` alive until every queued write and every open capture handle has closed. A producer that supports config reloads must retain guards for previous capture directories until their writers finish. A root UUID identifies persistent storage. It does not identify a process.

`resolve(observed_day, channel)` returns the filename for the greater of the observed day and the persisted day floor. It persists an advancing floor before returning. `open_append` also creates private directories and returns a read-and-append file handle. Event timestamps and JSONL payloads remain the caller's responsibility.

If state publication fails, the producer refuses further writes until it restarts with validated state. This includes an error after the state rename but before directory sync. Clock rollback and delayed records use the current storage-day bucket.

| Layout | Channel | Relative capture path |
| --- | --- | --- |
| `Proxy` | `Proxy` | `rust-YYYY-MM-DD.jsonl` |
| `Otel` | `Logs` | `YYYY-MM-DD/logs.jsonl` |
| `Otel` | `Traces` | `YYYY-MM-DD/traces.jsonl` |
| `Otel` | `Metrics` | `YYYY-MM-DD/metrics.jsonl` |

Unix capture files have mode `0600`. Newly enrolled roots and capture subdirectories have mode `0700`. Unix opens use `O_NOFOLLOW` and `O_NONBLOCK`, reject nonregular files, and reject extra hard links. Capture opens bind the root and each date directory to directory handles, then open the leaf through that handle. A substituted date-directory symlink cannot redirect an append or seal outside the root. Returned append handles support reading a partial tail without changing its bytes.

## Offline closure

`seal_offline(root, SealOptions)` takes the same producer lock. A running or detached producer prevents sealing. The operation keeps the union of these files:

- The latest `keep_latest` files by filename, per channel.
- The latest `keep_latest` files by modification time, per channel.
- Files within the `hot_days` window by either storage day or modification time.
- Files in the active storage day or any later day.
- Files on or after the exclusive `before` boundary.

`keep_latest` and `hot_days` must each be at least two. `only_relative_paths` optionally narrows the selected files while preserving every root-wide exclusion. Selected paths must match the enrolled layout. Missing selected sources are errors. Protected selected files appear in `SealReport.skipped` and are not hashed.

The operation advances the day floor before it hashes any selected source or publishes a receipt. A future producer cannot open those older paths through this crate, even if the source is later removed. Discovery records each source and parent identity, length, and change timestamps. Sealing revalidates that snapshot before reading any payload, streams SHA-256 with a 64 KiB buffer, syncs the source, and checks the snapshot again after reading. A replaced or newly touched source requires a fresh run with fresh reader exclusions. An empty file qualifies. A nonempty file must end in a newline. Partial tails remain untouched and have no seal.

Receipts publish without overwriting existing receipts. Repeated sealing verifies the same identity and bytes. A mismatch is an error. A failure can leave the floor advanced with no receipt; rerunning the operation completes closure. Recovery under the root lock removes only this crate's staged metadata files. It preserves capture payloads. Enrollment and offline recovery resync lifecycle directories and a bounded ancestor chain before acknowledging success, including visible entries left by a failed publication. Opening an append handle resyncs its validated parent even when the capture leaf already exists. These checks cover retries after a successful create or publication followed by a failed directory sync.

## Persistent metadata

Each enrolled root contains `.capture-root.json` and `.capture-state/`. The state directory contains `producer.lock`, `state.json`, and `seals/`. Never delete, replace, or copy these files to reset enrollment. Keep lifecycle metadata after raw capture retirement. The lock pathname remains permanent.

The root marker binds protocol version, root UUID, and layout. The state adds `capture_day_floor`. Each seal filename is the SHA-256 of its canonical relative capture path, with a `.json` suffix. A `CaptureSealV1` contains these fields:

| Field | Meaning |
| --- | --- |
| `protocol_version` | `1` |
| `root_uuid` | Original enrollment UUID |
| `layout`, `channel` | Capture layout and signal |
| `relative_path` | Canonical source path within the root |
| `identity` | Unix `device` and `inode` |
| `closed_length` | Full source byte length |
| `sha256` | SHA-256 of every source byte |
| `ends_with_newline` | True for an empty file or a final newline |
| `capture_day_floor` | Durable floor strictly after the source day |
| `sealed_at` | UTC closure timestamp |

`read_seal(root, relative_path)` validates the receipt against the current root marker and state. It checks protocol, UUID, layout, canonical path, channel, digest format, and day floor. It works after raw source retirement and does not read payloads. It does not prove archive recovery or equality with a current source file. Archive consumers must compare the full source identity, length, and digest with their verified checkpoint before any optional retirement.

Metadata reads are capped at 64 KiB each. Directory scans and selections are capped at 100,000 entries. Cold-path ancestor walks are capped at 128 directories. Source hashing has no payload-size limit and uses bounded memory. Sealing can require time proportional to the selected source bytes.

## Platform and trust limits

The minimum supported Rust version is 1.89 for standard file locks. Capture and explicit enrollment compile on Windows. Durable sealing and `read_seal` return `Unsupported` there because v1 requires Unix file identity and directory sync.

The contract covers producers that use this crate, within a root whose permanent lifecycle metadata stays intact. Stop older producers before adoption. A rollback binary must honor this protocol or use a separate capture root. Advisory locks cannot constrain an unrelated program that ignores them. Moving or replacing the root or its control directories while a producer runs breaks the contract.

A seal proves closure of the existing file bytes. Queue overflow, dropped records, crashes, and prior capture gaps remain separate coverage facts. This crate contains no source deletion operation and does not modify native agent transcripts.
