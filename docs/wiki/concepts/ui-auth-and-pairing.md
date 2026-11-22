# UI Authentication, OAuth SSO, and Device Pairing

> **Scope:** Web Console & Tauri Desktop UI  
> **Status:** Active / Production  
> **Last Updated:** 2026-11-21  

---

## 1. Overview

Xibalba Shield's user authentication architecture supports zero-trust operator access, web console single-sign-on (SSO), and cryptographic device pairing for headless or desktop agent environments.

Authentication is governed by three primary subsystems:
1. **Auth0 Universal OAuth / Social SSO**: Primary web authentication broker providing Google and GitHub identity verification.
2. **Local Scrypt Operator Auth**: Self-hosted, air-gapped credential storage using `scrypt` hashing and secure HttpOnly session cookies (`shield_session`).
3. **RFC 8628 OAuth 2.0 Device Authorization Grant**: Zero-trust cryptographic device pairing for autonomous nodes and desktop agents.

---

## 2. Auth0 OIDC Integration Architecture

```
User (Browser)
   │
   ├─► Click "Sign in with Google" / "Sign in with GitHub"
   │   └─► GET /api/shield/auth/auth0/authorize?connection=google-oauth2
   │       └─► 302 Redirect -> dev-2acdt0dlqgi0pqcu.us.auth0.com/authorize
   │
   ├─► Auth0 completes authentication with Google/GitHub IdP
   │   └─► 302 Redirect -> http://localhost:5173/#access_token=...&id_token=...
   │
   ├─► Frontend Client (ui/src/App.jsx) extracts tokens from URL hash
   │   └─► POST /api/shield/auth/auth0/session { id_token, access_token }
   │
   └─► Backend (shield/backend/auth0_auth.py)
       ├─► Decodes & validates RS256 JWT claims against Auth0 JWKS endpoint
       ├─► Validates audience (Yj3RdbTXctEWUQPYc2gLvQ7OTQkL5t6u) & issuer
       ├─► Resolves/creates account in Store (store.authenticate_or_create_oauth_account)
       └─► Sets HttpOnly 'shield_session' cookie & returns user profile
```

### Configuration Parameters

| Parameter | Environment Variable | Default Production Value | Description |
| :--- | :--- | :--- | :--- |
| **Domain** | `AUTH0_DOMAIN` | `dev-2acdt0dlqgi0pqcu.us.auth0.com` | Verified tenant host |
| **Client ID** | `AUTH0_CLIENT_ID` | `Yj3RdbTXctEWUQPYc2gLvQ7OTQkL5t6u` | Application OIDC client identifier |
| **JWKS URL** | N/A | `https://{domain}/.well-known/jwks.json` | Public key set for token verification |
| **Callback** | `AUTH0_CALLBACK_URL`| `http://localhost:5173/` | Whitelisted frontend return route |

---

## 3. UI Layout & Accessibility Standard

The authentication interface (`ui/src/components/SignIn.jsx`) adheres strictly to the **0-Scroll Reachability Standard**:
- **2-Column Responsive Card**: On standard viewports (>=1024px), the UI splits into a branding/SSO hero column on the left and an explicit credential form column on the right.
- **Immediate Action Fold**: All primary action buttons (Sign In, Create Account, Social SSO) are positioned well above the 720px vertical viewport limit without requiring user scrolling.
- **Enterprise Dark Aerospace Aesthetic**: High-contrast typography, subtle backdrop blur (`backdrop-filter: blur(12px)`), and accessible focus states for keyboard navigation.

---

## 4. Verification & Testing

- Token signature validation, claims extraction, and error handling are verified in `tests/test_auth0_auth.py`.
- Dual-provider fallback with backward-compatible endpoints is verified in `tests/test_supabase_auth.py`.
- End-to-end endpoint delivery is verified in `tests/test_backend.py`.
