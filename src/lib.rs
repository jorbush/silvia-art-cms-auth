pub mod oauth;

use uuid::Uuid;
use worker::*;

use crate::oauth::{
    build_github_authorize_url, build_state_cookie, clear_state_cookie, render_oauth_html,
    verify_oauth_state, ErrorPayload, GithubTokenResponse, HealthResponse, SuccessPayload,
    TokenExchangeRequest, DEFAULT_ALLOWED_ORIGIN, DEFAULT_SCOPE, GITHUB_TOKEN_URL,
};

fn cors_headers(allowed_origin: &str) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", allowed_origin)?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    )?;
    Ok(headers)
}

fn html_response(
    status_label: &str,
    payload: &impl serde::Serialize,
    allowed_origin: &str,
    clear_cookie: bool,
) -> Result<Response> {
    let body = render_oauth_html(status_label, payload, allowed_origin)
        .map_err(|e| Error::RustError(format!("Failed to serialize OAuth payload: {e}")))?;

    let headers = cors_headers(allowed_origin)?;
    headers.set("Content-Type", "text/html; charset=utf-8")?;
    if clear_cookie {
        headers.append("Set-Cookie", clear_state_cookie())?;
    }
    Ok(Response::ok(body)?.with_headers(headers))
}

fn env_var_or_default(env: &Env, key: &str, default: &str) -> String {
    env.var(key)
        .map(|v| v.to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_secret_or_var(env: &Env, key: &str) -> Option<String> {
    env.secret(key)
        .or_else(|_| env.var(key))
        .map(|v| v.to_string())
        .ok()
        .filter(|v| !v.is_empty())
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let allowed_origin = env_var_or_default(&env, "ALLOWED_ORIGIN", DEFAULT_ALLOWED_ORIGIN);

    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&allowed_origin)?));
    }

    match url.path() {
        "/" | "/health" => {
            let body = serde_json::to_string(&HealthResponse {
                status: "ok",
                service: "silvia-art-cms-auth",
            })
            .map_err(|e| Error::RustError(e.to_string()))?;
            let headers = cors_headers(&allowed_origin)?;
            headers.set("Content-Type", "application/json")?;
            Ok(Response::ok(body)?.with_headers(headers))
        }
        "/auth" => handle_auth(&url, &env),
        "/callback" => handle_callback(&req, &url, &env, &allowed_origin).await,
        _ => Ok(Response::error("Not Found", 404)?.with_headers(cors_headers(&allowed_origin)?)),
    }
}

fn handle_auth(url: &Url, env: &Env) -> Result<Response> {
    let Some(client_id) = env_secret_or_var(env, "GITHUB_CLIENT_ID") else {
        return Response::error("Missing GITHUB_CLIENT_ID", 500);
    };

    let scope = url
        .query_pairs()
        .find_map(|(k, v)| (k == "scope" && !v.is_empty()).then(|| v.into_owned()))
        .unwrap_or_else(|| DEFAULT_SCOPE.to_string());

    let state = Uuid::new_v4().to_string();
    let origin = url.origin().unicode_serialization();
    let redirect_uri = format!("{origin}/callback");

    let authorize_url = build_github_authorize_url(&client_id, &redirect_uri, &scope, &state)
        .map_err(|e| Error::RustError(format!("Invalid GitHub authorize URL: {e}")))?;

    let headers = Headers::new();
    headers.set("Location", &authorize_url)?;
    headers.append("Set-Cookie", &build_state_cookie(&state))?;

    Ok(Response::empty()?.with_status(302).with_headers(headers))
}

async fn handle_callback(
    req: &Request,
    url: &Url,
    env: &Env,
    allowed_origin: &str,
) -> Result<Response> {
    let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();

    if let Some(error) = query.get("error") {
        let message = query
            .get("error_description")
            .cloned()
            .unwrap_or_else(|| error.clone());
        return html_response(
            "error",
            &ErrorPayload { error: &message },
            allowed_origin,
            true,
        );
    }

    let cookie_header = req.headers().get("Cookie").ok().flatten();
    let query_state = query.get("state").map(String::as_str);

    if !verify_oauth_state(query_state, cookie_header.as_deref()) {
        return html_response(
            "error",
            &ErrorPayload {
                error: "Invalid or missing OAuth state parameter",
            },
            allowed_origin,
            true,
        );
    }

    let Some(code) = query.get("code").filter(|c| !c.is_empty()) else {
        return html_response(
            "error",
            &ErrorPayload {
                error: "Missing authorization code",
            },
            allowed_origin,
            true,
        );
    };

    let (Some(client_id), Some(client_secret)) = (
        env_secret_or_var(env, "GITHUB_CLIENT_ID"),
        env_secret_or_var(env, "GITHUB_CLIENT_SECRET"),
    ) else {
        return html_response(
            "error",
            &ErrorPayload {
                error: "Server OAuth configuration missing",
            },
            allowed_origin,
            true,
        );
    };

    let payload = TokenExchangeRequest {
        client_id: &client_id,
        client_secret: &client_secret,
        code,
    };

    let json_body = serde_json::to_string(&payload)
        .map_err(|e| Error::RustError(format!("Serialization error: {e}")))?;

    let req_headers = Headers::new();
    req_headers.set("Content-Type", "application/json")?;
    req_headers.set("Accept", "application/json")?;
    req_headers.set("User-Agent", "silvia-art-cms-auth")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(req_headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&json_body)));

    let outbound_req = Request::new_with_init(GITHUB_TOKEN_URL, &init)?;
    let mut github_res = match Fetch::Request(outbound_req).send().await {
        Ok(res) => res,
        Err(err) => {
            let msg = format!("Token exchange request failed: {err}");
            return html_response("error", &ErrorPayload { error: &msg }, allowed_origin, true);
        }
    };

    let token_data: GithubTokenResponse = match github_res.json().await {
        Ok(data) => data,
        Err(err) => {
            let msg = format!("Failed to parse GitHub token response: {err}");
            return html_response("error", &ErrorPayload { error: &msg }, allowed_origin, true);
        }
    };

    if let Some(access_token) = token_data.access_token.filter(|t| !t.is_empty()) {
        return html_response(
            "success",
            &SuccessPayload {
                token: &access_token,
                provider: "github",
            },
            allowed_origin,
            true,
        );
    }

    let err_msg = token_data
        .error_description
        .or(token_data.error)
        .unwrap_or_else(|| "Failed to exchange token with GitHub".to_string());

    html_response(
        "error",
        &ErrorPayload { error: &err_msg },
        allowed_origin,
        true,
    )
}
