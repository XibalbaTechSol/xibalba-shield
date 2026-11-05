# Xibalba Shield device app

A tray app for the endpoint. It answers one question the CLI makes awkward: **what has Shield
frozen on this machine right now, and how do I undo it?**

It is the operator's local observer and manual override for the loop Shield closes on the device.
It reads the files Shield writes, checks them against the operating system, and runs the audited
`shield resume` command. It never sends signals itself.

## Status: read before relying on it

| Part | Status |
|---|---|
| `device-core` (Rust: log reading, frozen-process derivation, resume command) | **Tested.** 19 unit + 3 contract tests, `cargo test` |
| `device-core` against real Shield output | **Tested.** Golden fixtures were produced by the real Python writers; `tests/test_device_contract.py` fails if the Python shape drifts |
| Web UI (`src/`) | **Tested.** 8 Playwright specs drive the real bridge by providing `window.__TAURI_INTERNALS__` as the Tauri runtime does |
| `src-tauri` (tray, window, the two commands) | **NOT built or run.** It needs the platform webview libraries (webkit2gtk on Linux), which the build sandbox lacked. Written against the Tauri 2 API; compile and exercise it before use |
| Windows / macOS | Process-state checking needs `/proc`, so freezes there show as *Unverified*. Tray and UI are untested on those platforms |

## What it shows

- **Frozen processes**, derived from `outcomes.jsonl` (written by `shield run`) and checked against
  `/proc/<pid>/stat`. The headline counts only freezes the OS shows as stopped. A freeze the log
  records but the OS shows running is labelled *Running (log says frozen)*, not trusted.
- **Resume**, offered only where it means something (stopped or unverifiable), with a confirm step.
- **Recent decisions** from `decisions.jsonl`.
- **Notes**: a missing log, truncation, or unreadable lines are stated, never hidden.

## Run

```bash
# 1. Shield must be writing logs (the default directory is ~/.xibalba-shield)
shield run ...

# 2. Tested parts (no GUI needed)
cd device-app
cargo test                 # device-core
npm install && npm run build && npm run test:e2e

# 3. The desktop app (needs webkit2gtk-4.1 dev packages on Linux)
npm run tauri dev          # or: npm run tauri build
npm run tauri icon icons/icon.png   # generates the .ico/.icns bundles need
```

Environment variables read by the shell:

| Variable | Meaning |
|---|---|
| `SHIELD_DATA_DIR` | Directory holding `decisions.jsonl` and `outcomes.jsonl` (default `~/.xibalba-shield`) |
| `SHIELD_BIN` | Path to the `shield` executable (default `shield` on `PATH`) |
| `SHIELD_DEVICE_CONFIG` | Optional device config; lets `shield resume` tell the backend so the resume counts toward the fleet false-freeze rate |

## Security notes

- The webview is granted `core:default` only: no filesystem, shell, or opener plugin. The two Rust
  commands are the only way the UI touches the device.
- The pid and event id are validated in `device-core` and the command is spawned as an argument
  vector, never through a shell. A leading `-` in an event id is rejected, and ids are passed as
  `--event-id=<value>`, so a log entry cannot inject an option.
- `outcomes.jsonl` is written `0600` in a `0700` directory because it names processes on the device.

## Layout

```
device-core/   plain Rust, no GUI dependency; where the logic and tests live
src-tauri/     thin native shell: tray, window, two commands
src/           React UI
e2e/           Playwright specs
```
