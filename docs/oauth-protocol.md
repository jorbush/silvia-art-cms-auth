# OAuth 2.0 & Sveltia CMS Handshake Protocol

Sveltia CMS (and Decap CMS) uses a browser popup flow to authenticate with GitHub without exposing `GITHUB_CLIENT_SECRET` in client-side code.

## Sequence Flow

```mermaid
sequenceDiagram
    participant CMS as Sveltia CMS (/admin/)
    participant Popup as Popup Window (Worker)
    participant GH as GitHub OAuth

    CMS->>Popup: window.open("/auth?scope=public_repo")
    Popup->>Popup: Generate UUID v4 state + Set-Cookie oauth_state
    Popup-->>GH: 302 Redirect /login/oauth/authorize
    GH-->>Popup: 302 Redirect /callback?code=...&state=...
    Popup->>Popup: Constant-time verify state == cookie
    Popup->>GH: POST /login/oauth/access_token
    GH-->>Popup: { access_token }
    Popup->>CMS: postMessage("authorizing:github", "*")
    CMS-->>Popup: Reply message from opener origin
    Popup->>Popup: Validate e.origin against ALLOWED_ORIGIN
    Popup->>CMS: postMessage("authorization:github:success:{token,provider}", e.origin)
    Popup->>Popup: window.close()
```

## Security Controls

1. **CSRF State Cookie**: `/auth` generates a random UUID v4 `state` and stores it in `oauth_state` with `HttpOnly; Secure; SameSite=Lax; Path=/callback; Max-Age=300`. `/callback` compares query `state` against the cookie in constant time and clears the cookie immediately.
2. **Origin Validation**: The callback HTML script verifies `e.origin` matches `ALLOWED_ORIGIN` (or `.github.io`) before transmitting the token via `window.opener.postMessage`.
3. **Script Injection Escaping**: Serialized JSON payloads escape `\`, `'`, `<`, and `>` before embedding into the inline JavaScript template.
