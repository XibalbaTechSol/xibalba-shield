# macOS Agent Runbook

This runbook turns the `shield run` daemon into a supervised macOS system service managed by Darwin's `launchd`, alongside deploying the native Tauri v2 Desktop App (`.dmg` / `.app`).

---

## Architecture on Darwin / macOS

On macOS, Shield operates across two tiers without requiring Linux-specific `systemd` or `eBPF`:
1. **Desktop App (`device-app/`)**: Native Tauri v2 client compiled as a **Universal Mach-O binary (`arm64` + `x86_64`)**, delivering the dark glassmorphism cockpit, dual-agent closed-loop controls, Confined Agent DID, hardware network telemetry, and manual process resume.
2. **Background Daemon (`shield run`)**: Managed by a root LaunchDaemon (`com.xibalba.shield.plist`) loaded into `launchd` system domain (`/Library/LaunchDaemons/`). It runs the deterministic OPA policy engine, local pre-tool gate socket, RFC 8628 pairing, and Integrity Protocol telemetry exporter.

---

## 1. Prerequisites

- **macOS**: macOS 12 (Monterey), 13 (Ventura), 14 (Sonoma), or 15+ (Sequoia) running on Apple Silicon (M1/M2/M3/M4) or Intel.
- **Python**: Python 3.10+ (recommend Python 3.12 via Homebrew or system).
- **Open Policy Agent (OPA)**:
  ```bash
  # Apple Silicon
  sudo curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v1.18.2/opa_darwin_arm64
  # Intel
  # sudo curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v1.18.2/opa_darwin_amd64
  sudo chmod +x /usr/local/bin/opa
  ```

---

## 2. Desktop App Installation (`.dmg`)

1. Download or locate `Xibalba Shield_0.1.0_universal.dmg` (available in repository release artifacts or CI builds under `.github/workflows/build-desktop-macos.yml`).
2. Double-click the `.dmg` file to mount it.
3. Drag **Xibalba Shield.app** into `/Applications`.
4. Launch the application from Spotlight or `/Applications/Xibalba Shield.app`.
   *(If prompted with Gatekeeper warning for unsigned internal build: right-click and select "Open", or run `xattr -cr "/Applications/Xibalba Shield.app"`)*.

---

## 3. Background Agent Installation (`scripts/install_macos_agent.sh`)

To install the supervised CLI and LaunchDaemon:

```bash
# Clone or navigate to the repository
git clone https://github.com/XibalbaTechSol/xibalba-shield.git
cd xibalba-shield

# Run the automated installer as root
sudo bash scripts/install_macos_agent.sh
```

### What the Installer Configures
- Creates the dedicated directories:
  - Configuration: `/etc/xibalba-shield` (mode `0755`)
  - Policies: `/etc/xibalba-shield/policies` (mode `0755`)
  - Logs: `/var/log/xibalba-shield` (mode `0755`)
  - State: `/Library/Application Support/xibalba-shield` (mode `0755`)
- Copies the runner script to `/Library/Application Support/xibalba-shield/xibalba-shield-run.sh` (mode `0755`).
- Copies default policy bundle (`policies/defaults/smb.json`) to `/etc/xibalba-shield/policies/current.json`.
- Installs LaunchDaemon plist to `/Library/LaunchDaemons/com.xibalba.shield.plist` (owned by `root:wheel`, mode `0644`).
- Bootstraps and kicks off the service:
  ```bash
  launchctl bootstrap system /Library/LaunchDaemons/com.xibalba.shield.plist
  launchctl kickstart -k system/com.xibalba.shield
  ```

---

## 4. Service Management via `launchctl`

macOS uses `launchctl` instead of `systemctl`:

| Operation | Command |
|---|---|
| **Check Status** | `sudo launchctl list | grep xibalba` |
| **Inspect Detailed Service State** | `sudo launchctl print system/com.xibalba.shield` |
| **Restart Service** | `sudo launchctl kickstart -k system/com.xibalba.shield` |
| **Stop / Unload** | `sudo launchctl bootout system /Library/LaunchDaemons/com.xibalba.shield.plist` |
| **Start / Load** | `sudo launchctl bootstrap system /Library/LaunchDaemons/com.xibalba.shield.plist` |

---

## 5. Log Files & Verification

Logs are streamed directly to `/var/log/xibalba-shield/`:

```bash
# Inspect daemon standard out / operational events
tail -f /var/log/xibalba-shield/daemon.log

# Inspect errors and crash output
tail -f /var/log/xibalba-shield/daemon.err

# Inspect decision ledger
tail -f /var/log/xibalba-shield/decisions.jsonl
```

---

## 6. Pairing with Shield Cloud Console

To pair your macOS endpoint with the cloud control plane (`https://xibalba-shield.onrender.com`):

1. Ensure the local loopback listener is active (or run `shield pair`):
   ```bash
   shield pair --tenant <your-tenant-id>
   ```
2. Complete the RFC 8628 Device Authorization code verification displayed in your terminal or Desktop App.
3. The cryptographic keypair is generated and stored locally:
   - Private key: `~/.shield/did/private_key.pem` (enforced POSIX `0600`)
   - Device config: `~/.shield/device.json`
4. The Desktop App will immediately reflect the paired tenant and Confined Agent DID.

---

## 7. Known Differences & Gaps on Darwin

1. **Kernel Sensing**: Native eBPF is a Linux-only kernel feature. On macOS, Shield enforces semantic tool-use guardrails, OPA policy evaluation, and Landlock/process barriers. Native kernel system call interception via Apple Endpoint Security (`libEndpointSecurity.dylib`) is tracked on the post-freeze roadmap (see `docs/SUPPORTED_MATRIX.md`).
2. **Process Inspection**: Because macOS lacks `/proc`, process liveness checks in `device-core` use POSIX signal probes (`kill(pid, 0)`).
3. **AF_UNIX Socket Limits**: Darwin enforces a strict 104-byte limit on Unix socket paths (compared to Linux's 108 bytes). All gate sockets must reside in short directory paths.
4. **Directory Permissions**: APFS strips the setgid `0o2000` bit for non-root accounts; spool directories enforce `0770` permissions.
