# Android & Mobile Agent Companion Runbook

This runbook documents the deployment, operation, and security architecture of **Xibalba Shield on Android and mobile endpoints**, including the native Tauri v2 mobile companion application (`.apk`) and mobile AI agent confinement models.

---

## Mobile Security Architecture

Mobile operating systems (Android and iOS) enforce strict application sandboxing, preventing external processes from injecting eBPF tracing probes or issuing POSIX signals (`SIGSTOP`, `SIGCONT`) across application boundaries without root privileges. 

To deliver the same enterprise-grade guarantees on mobile as on Linux and macOS, Xibalba Shield operates across three complementary pillars:

```text
       +---------------------------------------------------------+
       |                  Mobile Endpoint Device                 |
       |                                                         |
       |  +------------------------+  +-----------------------+  |
       |  |     Mobile AI App      |  |  Shield Companion     |  |
       |  |  (Agent / Assistant)   |  |     (Tauri v2 APK)    |  |
       |  |                        |  |                       |  |
       |  |  +------------------+  |  |  +-----------------+  |  |
       |  |  | In-Process SDK   |  |  |  | Hardware Keystore|  |  |
       |  |  | (OPA PreToolUse) |  |  |  | DID:integrity   |  |  |
       |  |  +--------+---------+  |  |  +--------+--------+  |  |
       |  +-----------|------------+  +-----------|-----------+  |
       |              |                           |              |
       |              | Inter-App IPC /           | Biometric    |
       |              | Intent Escalation         | Approval     |
       |              +--------------------------->              |
       |                                                         |
       |  +---------------------------------------------------+  |
       |  |     Local Loopback VPN Engine (VpnService)        |  |
       |  |  - Intercepts tool network egress (MCP / REST)    |  |
       |  |  - Zero-trust model routing enforcement           |  |
       |  +---------------------------------------------------+  |
       +---------------------------------------------------------+
```

1. **In-Process Mobile Agent SDK**: Embedded directly within mobile agent runtimes (Hermes Mobile, mobile assistants, local LLM apps). Evaluates tool invocations against local OPA rules in `< 5 ms` prior to execution.
2. **Local Loopback VPN Filter (`VpnService`)**: Captures mobile tool egress and model traffic without root privileges, blocking unauthorized exfiltration channels and data leaks.
3. **Mobile Companion Application (`device-app/`)**: A native Tauri v2 + Kotlin application (`com.xibalba.shield.device`) providing:
   - **Hardware-Backed Keystore DID**: Keys generated inside the Android Keystore / StrongBox HSM (`did:integrity:...`), ensuring private keys cannot be extracted.
   - **Biometric HITL Escalation**: Operators approve high-risk agent tool calls via fingerprint or facial recognition before execution.
   - **Real-Time Security Cockpit**: Visualizes device identity, active network telemetry, and policy decision audit chains.

---

## 1. Prerequisites

To build the Android companion package locally:

- **OS**: Linux or macOS host with Docker or native developer tools.
- **Node.js**: Node 22+ with `npm`
- **Rust**: `rustup` with targets:
  ```bash
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- **Java**: OpenJDK 17 (`JAVA_HOME`)
- **Android SDK & NDK**:
  - Android SDK Platform `android-34` (or `android-36` / `android-37`)
  - Android SDK Build-Tools `34.0.0` or `36.0.0`
  - Android NDK `26.3.11579264`
  - Environment variables:
    ```bash
    export ANDROID_HOME="/home/xibalba/android/sdk"
    export NDK_HOME="/home/xibalba/android/sdk/ndk/26.3.11579264"
    export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
    ```

---

## 2. Building the Android Package (`.apk`)

From the `device-app` directory:

```bash
cd device-app

# 1. Install dependencies
npm ci

# 2. Build web frontend assets
npm run build

# 3. Initialize Android Studio harness (if first time)
npx tauri android init --ci

# 4. Compile native Rust shared library and package APK for aarch64 (ARM64)
npx tauri android build --apk --debug --target aarch64
```

### Build Outputs
The resulting binary is assembled at:
```text
device-app/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

For immediate access, the build artifact is copied to:
```text
/home/xibalba/Downloads/Xibalba_Shield_0.1.0_debug.apk
```

---

## 3. Package Verification & Analysis

Inspect the built APK using the Android SDK `apkanalyzer` CLI:

```bash
# Print package ID, version code, and version name
apkanalyzer apk summary /home/xibalba/Downloads/Xibalba_Shield_0.1.0_debug.apk
# Output: com.xibalba.shield.device  1000  0.1.0

# Verify bundled native JNI libraries
apkanalyzer files list /home/xibalba/Downloads/Xibalba_Shield_0.1.0_debug.apk | grep "lib/"
# Output:
# /lib/
# /lib/arm64-v8a/
# /lib/arm64-v8a/libshield_device_app_lib.so
```

---

## 4. Device Sideloading & Installation via ADB

Connect an Android physical device or start an Android Virtual Device (AVD) emulator, ensuring USB Debugging is active in Developer Options:

```bash
# Verify connected device
adb devices

# Install APK onto device
adb install -r /home/xibalba/Downloads/Xibalba_Shield_0.1.0_debug.apk

# Launch the Xibalba Shield application
adb shell am start -n com.xibalba.shield.device/.MainActivity
```

---

## 5. Pairing with the Cloud Control Plane

1. Open **Xibalba Shield** on the mobile device.
2. The app initializes its local DID identity (`did:integrity:<keystore_pubkey>`) and displays an RFC 8628 pairing code.
3. On the administrator workstation or mobile browser, navigate to the Cloud Console:
   ```text
   https://xibalba-shield.onrender.com
   ```
4. Enter the device pairing code under **Pair New Device** to associate the mobile companion with the tenant (`jacob-v-universe-org`).
5. Real-time telemetry, tool invocation escalations, and audit bundle receipts will stream to the cloud control plane.

---

## 6. Continuous Integration (GitHub Actions)

The mobile pipeline is automated in `.github/workflows/build-mobile-android.yml`.

On every push to `device-app/**` or manual `workflow_dispatch`:
- Sets up Java 17 and Android SDK/NDK 26.
- Compiles the Rust core for `aarch64-linux-android`.
- Builds the Vite web assets.
- Assembles the debug universal APK.
- Publishes the `.apk` as a workflow artifact (`xibalba-shield-mobile-android`).
