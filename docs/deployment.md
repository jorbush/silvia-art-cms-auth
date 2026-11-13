# Deploying `silvia-art-cms-auth`

## 1. Register a GitHub OAuth Application

1. Go to GitHub → **Settings** → **Developer settings** → **OAuth Apps** → **New OAuth App**.
2. Set:
   - **Application name**: `Silvia Art CMS`
   - **Homepage URL**: `https://jorbush.github.io/silvia-art-content/admin/`
   - **Authorization callback URL**: `https://silvia-art-cms-auth.<your-subdomain>.workers.dev/callback`
3. Save the **Client ID** and generate a **Client Secret**.

## 2. Configure `wrangler.jsonc`

Update `vars.ALLOWED_ORIGIN` in `wrangler.jsonc` if your CMS admin is hosted on a custom domain instead of `https://jorbush.github.io`.

## 3. Deploy with Wrangler

```bash
npx wrangler login
npx wrangler deploy
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
```

## 4. Verify Health Endpoint

```bash
curl https://silvia-art-cms-auth.<your-subdomain>.workers.dev/health
# {"status":"ok","service":"silvia-art-cms-auth"}
```
