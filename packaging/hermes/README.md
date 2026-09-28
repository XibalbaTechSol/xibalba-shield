# Hermes profiles for Shield

Version-controlled copies of the Hermes profile files that define Shield's agent. They live at
runtime under `~/.hermes/profiles/<name>/`; `scripts/install_hermes_analyst.sh` installs or
refreshes the analyst profile from here.

| Profile | Role | Files here |
|---|---|---|
| `xibalba-shield` | Shield's identity (its DID) and interactive agent; Cortex memory `~/.hermes/xibalba-cortex-shield` | `SOUL.md` only. `config.yaml` holds machine paths and stays local. |
| `xibalba-shield-analyst` | Toolless, memory-off judgment step used by `shield/hermes_analyst.py` | `config.yaml`, `SOUL.md` |

The analyst's `config.yaml` isolates by omission: no `mcp_servers`, `plugins` or `hooks`, and
memory off. `shield-hermes-analyst --preflight` proves the built agent sends zero tool schemas,
and fails closed otherwise. Credentials are never stored here: the profile falls back to the
shared Hermes Codex login.
