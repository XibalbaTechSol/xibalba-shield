# Deploying Xibalba Shield on Render with Google OAuth / OIDC

This guide details how to configure and deploy the **Xibalba Shield Control Plane** on [Render](https://render.com) with production-grade Google OAuth 2.0 / OpenID Connect (OIDC) social login.

---

## 1. Overview & Architecture

Shield implements an RFC 7636 (PKCE S256) and HMAC-SHA256 signed-state flow to protect operators against CSRF, replay attacks, and session fixation.

```
┌─────────────────┐       1. Click "Sign in with Google"       ┌──────────────────────┐
│                 ├───────────────────────────────────────────►│                      │
│   Operator      │       2. Redirect with PKCE + Signed State │    Shield Backend    │
│    Browser      │◄───────────────────────────────────────────┤     (Render Web)     │
│                 │                                            └──────────────────────┘
│                 │       3. Authenticate & Grant Consent
│                 ├───────────────────────────────────────────►┌──────────────────────┐
│                 │                                            │     Google OIDC      │
│                 │       4. Redirect with Authorization Code  │    (OAuth 2.0)       │
│                 │◄───────────────────────────────────────────┤                      │
│                 │                                            └──────────────────────┘
│                 │       5. Callback: /api/shield/auth/oidc/callback?code=...&state=...
│                 ├───────────────────────────────────────────►┌──────────────────────┐
│                 │                                            │                      │
│                 │       6. Server-to-Server Token Exchange   │    Shield Backend    │
│                 │          & ID Token Signature Verification ├──────────────────────► Google Token API
│                 │                                            │◄───────────────────── (tokens)
│                 │       7. Set HttpOnly Session Cookie       │
│                 │◄───────────────────────────────────────────┤  Issues session token
└─────────────────┘                                            └──────────────────────┘
```

### Key Security Properties
- **PKCE (S256):** Prevents authorization code interception attacks.
- **HMAC-SHA256 Signed State:** State token includes a tamper-proof cryptographically signed JSON payload binding the `code_verifier`, provider, and TTL (10 minutes) against `SESSION_SECRET`.
- **Verified Email Requirement:** Only accounts with `email_verified == true` returned by Google can authenticate or auto-provision.
- **HttpOnly Secure Session Cookie:** Session tokens are delivered via `Set-Cookie` with `HttpOnly`, `SameSite=Strict`, and `Secure` flags, isolating operator tokens from JavaScript exfiltration.

---

## 2. Google Cloud Console Setup

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Select your Google Cloud project (or create one, e.g. `xibalba-shield-production`).
3. Navigate to **APIs & Services** > **OAuth consent screen**:
   - User Type: **External** (or **Internal** if restricting to Google Workspace domain).
   - App Name: `Xibalba Shield`.
   - User support email: Enter your administrative contact email.
   - Developer contact email: Enter your technical contact email.
   - Scopes: Add `openid`, `.../auth/userinfo.email`, and `.../auth/userinfo.profile`.
4. Navigate to **APIs & Services** > **Credentials**:
   - Click **Create Credentials** > **OAuth client ID**.
   - Application type: **Web application**.
   - Name: `Xibalba Shield Render Web Service`.
   - **Authorized JavaScript origins**:
     - Production: `https://<your-service-name>.onrender.com`
     - Custom domain (if applicable): `https://shield.yourcompany.com`
     - Local development: `http://localhost:8435` and `http://127.0.0.1:8435`
   - **Authorized redirect URIs**:
     - Production: `https://<your-service-name>.onrender.com/api/shield/auth/oidc/callback`
     - Custom domain: `https://shield.yourcompany.com/api/shield/auth/oidc/callback`
     - Local development: `http://localhost:8435/api/shield/auth/oidc/callback`
5. Save and copy:
   - **Client ID** (e.g. `123456789-abcdef.apps.googleusercontent.com`)
   - **Client Secret** (e.g. `GOCSPX-xxxxxxxxxxxxxxxxxxxx`)

---

## 3. Render Web Service Deployment

### Method A: Render CLI (Fastest & Automated)

Using the official [Render CLI](https://render.com/docs/cli):

```bash
# 1. Verify you are authenticated to your Render workspace
render whoami
render workspace current

# 2. Deploy Xibalba Shield web service with Google OAuth configured
render services create \
  --name xibalba-shield \
  --type web_service \
  --repo https://github.com/XibalbaTechSol/xibalba-shield \
  --branch main \
  --runtime python \
  --build-command "pip install --upgrade uv && uv sync --extra dev && (cd ui && npm ci && npm run build)" \
  --start-command "uv run shield-backend --host 0.0.0.0 --port \$PORT" \
  --health-check-path /api/shield/health \
  --plan free \
  --region oregon \
  --env-var GOOGLE_CLIENT_ID="<your-google-client-id>.apps.googleusercontent.com" \
  --env-var GOOGLE_CLIENT_SECRET="<your-google-client-secret>" \
  --env-var OIDC_REDIRECT_URI="https://xibalba-shield.onrender.com/api/shield/auth/oidc/callback" \
  --env-var SESSION_SECRET="$(openssl rand -hex 32)" \
  --env-var SHIELD_BACKEND_TOKEN="$(openssl rand -hex 16)" \
  --env-var HOST="0.0.0.0"

# 3. View deployment logs in real time
render logs srv-<service-id>
```

### Method B: Render Blueprint (`render.yaml` Infrastructure as Code)

The repository includes a validated `render.yaml` Blueprint definition.

1. Validate the blueprint locally:
   ```bash
   render blueprints validate ./render.yaml
   ```
2. In Render Dashboard, click **New +** > **Blueprint**, connect `XibalbaTechSol/xibalba-shield`, and Render will parse `render.yaml`.
3. Provide the un-synced values (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `OIDC_REDIRECT_URI`). `SESSION_SECRET` and `SHIELD_BACKEND_TOKEN` will be generated cryptographically by Render automatically.

### Method C: Render Dashboard Manual Setup

1. In Render Dashboard, click **New +** > **Web Service**.
2. Connect `XibalbaTechSol/xibalba-shield`.
3. Runtime: **Python 3**.
4. Build Command: `pip install --upgrade uv && uv sync --extra dev && (cd ui && npm ci && npm run build)`
5. Start Command: `uv run shield-backend --host 0.0.0.0 --port $PORT`
6. Health Check Path: `/api/shield/health`

---

## 4. Environment Variables on Render

In the Render Dashboard under **Environment**:

| Variable Name | Required | Example / Description |
|:---|:---:|:---|
| `GOOGLE_CLIENT_ID` | **Yes** | `123456789-abcdef.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | **Yes** | `GOCSPX-xxxxxxxxxxxxxxxxxxxx` |
| `OIDC_REDIRECT_URI` | **Yes** | `https://<your-service-name>.onrender.com/api/shield/auth/oidc/callback` |
| `SESSION_SECRET` | **Yes** | High-entropy 64-char hex string (e.g. `openssl rand -hex 32`) used to sign OAuth state tokens |
| `SHIELD_BACKEND_TOKEN` | **Yes** | Persistent admin master token for API / operator CLI access |
| `SHIELD_PUBLIC_BASE_URL` | Optional | `https://<your-service-name>.onrender.com` |
| `HOST` | Recommended | `0.0.0.0` (Shield defaults to Render's `$PORT` and `0.0.0.0`) |
| `SHIELD_BACKEND_DB` | Optional | `/var/lib/xibalba-shield/shield.sqlite3` (when persistent disk mounted) |

---

## 5. Verification & Testing Playbook

### Step 1: Health & Provider Check
Check that the server is running and Google OAuth provider is detected:
```bash
curl -s https://<your-service-name>.onrender.com/api/shield/auth/providers
# Expected response:
# {"google": true}
```

### Step 2: Test OAuth Login Initialization
Request the login endpoint programmatically:
```bash
curl -s https://<your-service-name>.onrender.com/api/shield/auth/oidc/login
# Expected response:
# {
#   "redirect_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&code_challenge=...&state=...",
#   "state": "..."
# }
```

### Step 3: End-to-End Browser Sign-In
1. Navigate to `https://<your-service-name>.onrender.com/` in your browser.
2. Click **Sign in with Google**.
3. Complete authentication on Google's consent screen.
4. Verify browser is redirected back to `https://<your-service-name>.onrender.com/`.
5. Open Developer Tools > **Application** > **Cookies**:
   - Verify `shield_session` cookie is present with `HttpOnly`, `SameSite=Strict`, `Secure`.
6. Inspect the dashboard: the operator account name and newly provisioned organization tenant are displayed.
