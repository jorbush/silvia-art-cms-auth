# Silvia Art CMS Auth (Rust Cloudflare Worker)

A lightweight Cloudflare Worker written in **Rust** (`workers-rs` / `worker`) implementing the GitHub OAuth 2.0 exchange protocol and `postMessage` handshake for **Sveltia CMS** on `jorbush/silvia-art-content`.

## Endpoints

| Route | Method | Description |
| --- | --- | --- |
| `/` or `/health` | `GET` | Health check returning `{ "status": "ok", "service": "silvia-art-cms-auth" }` |
| `/auth` | `GET` | Generates CSRF `state`, sets `HttpOnly` cookie, and redirects to GitHub OAuth |
| `/callback` | `GET` | Validates CSRF `state`, exchanges `code` for access token, and returns Sveltia CMS handshake HTML |

## Quick Deployment

1. **Create a GitHub OAuth App** under `jorbush` → **Settings** → **Developer Settings** → **OAuth Apps** → **New OAuth App**:
   - **Homepage URL**: `https://jorbush.github.io/silvia-art-content/admin/`
   - **Authorization callback URL**: `https://silvia-art-cms-auth.<your-subdomain>.workers.dev/callback`

2. **Install Rust WASM target & Wrangler**:
   ```bash
   rustup target add wasm32-unknown-unknown
   cargo install worker-build
   npx wrangler login
   ```

3. **Deploy & configure secrets**:
   ```bash
   npx wrangler deploy
   npx wrangler secret put GITHUB_CLIENT_ID
   npx wrangler secret put GITHUB_CLIENT_SECRET
   ```

4. **Point `silvia-art-content` to the Worker** in `admin/config.yml`:
   ```yaml
   backend:
     name: github
     repo: jorbush/silvia-art-content
     branch: main
     base_url: https://silvia-art-cms-auth.<your-subdomain>.workers.dev
     auth_endpoint: auth
   ```

## Local Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --target wasm32-unknown-unknown
```

## Documentation

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [OAuth Protocol & Security](./docs/oauth-protocol.md)
- [Deployment Guide](./docs/deployment.md)
