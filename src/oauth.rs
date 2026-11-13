use serde::{Deserialize, Serialize};
use url::Url;

pub const DEFAULT_ALLOWED_ORIGIN: &str = "https://jorbush.github.io";
pub const DEFAULT_SCOPE: &str = "public_repo";
pub const OAUTH_STATE_COOKIE: &str = "oauth_state";
pub const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

#[derive(Debug, Serialize)]
pub struct HealthResponse<'a> {
    pub status: &'a str,
    pub service: &'a str,
}

#[derive(Debug, Serialize)]
pub struct TokenExchangeRequest<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub code: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct GithubTokenResponse {
    pub access_token: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SuccessPayload<'a> {
    pub token: &'a str,
    pub provider: &'a str,
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload<'a> {
    pub error: &'a str,
}

/// Build the GitHub OAuth authorization redirect URL.
pub fn build_github_authorize_url(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
) -> Result<String, url::ParseError> {
    let mut auth_url = Url::parse(GITHUB_AUTHORIZE_URL)?;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("state", state);
    Ok(auth_url.into())
}

/// Build the `Set-Cookie` header value for the CSRF `oauth_state` cookie.
pub fn build_state_cookie(state: &str) -> String {
    format!(
        "{OAUTH_STATE_COOKIE}={state}; HttpOnly; Secure; SameSite=Lax; Path=/callback; Max-Age=300"
    )
}

/// Build the clearing `Set-Cookie` header value after callback verification.
pub fn clear_state_cookie() -> &'static str {
    "oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/callback; Max-Age=0"
}

/// Extract a named cookie value from an HTTP `Cookie` header.
pub fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|pair| {
        let trimmed = pair.trim();
        let (key, value) = trimmed.split_once('=')?;
        if key.trim() == name {
            Some(value.trim())
        } else {
            None
        }
    })
}

/// Constant-time byte comparison for CSRF state tokens.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.bytes().zip(b.bytes()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Validate the `state` query param against the `oauth_state` cookie.
pub fn verify_oauth_state(query_state: Option<&str>, cookie_header: Option<&str>) -> bool {
    let Some(state) = query_state.filter(|s| !s.is_empty()) else {
        return false;
    };
    let Some(cookies) = cookie_header else {
        return false;
    };
    let Some(cookie_state) = extract_cookie(cookies, OAUTH_STATE_COOKIE) else {
        return false;
    };
    constant_time_eq(state, cookie_state)
}

/// Escape JSON for safe embedding inside a single-quoted JS string literal and `<script>` block.
pub fn escape_json_for_inline_script(json: &str) -> String {
    json.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}

/// Render the HTML popup document implementing Sveltia/Decap CMS `postMessage` handshake.
pub fn render_oauth_html<T: Serialize>(
    status: &str,
    payload: &T,
    allowed_origin: &str,
) -> Result<String, serde_json::Error> {
    let payload_json = serde_json::to_string(payload)?;
    let escaped_payload = escape_json_for_inline_script(&payload_json);
    let allowed_origin_json = serde_json::to_string(allowed_origin)?;

    Ok(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Authorizing Silvia Art CMS</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: #f7fafc;
      color: #2d3748;
    }}
    .card {{
      background: #fff;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.05);
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Connecting to GitHub...</h2>
    <p>This window will close automatically once authentication completes.</p>
  </div>
  <script>
    (function() {{
      const allowedOrigin = {allowed_origin_json};
      function receiveMessage(e) {{
        if (allowedOrigin !== '*' && e.origin !== allowedOrigin && !e.origin.endsWith('.github.io')) {{
          console.warn('Rejected postMessage from untrusted origin:', e.origin);
          return;
        }}
        window.opener.postMessage(
          'authorization:github:{status}:{escaped_payload}',
          e.origin
        );
        window.close();
      }}
      window.addEventListener('message', receiveMessage, false);
      window.opener.postMessage('authorizing:github', '*');
    }})();
  </script>
</body>
</html>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_github_authorize_url_with_params() {
        let result = build_github_authorize_url(
            "client_123",
            "https://auth.example.workers.dev/callback",
            "repo",
            "state-abc",
        )
        .expect("should build valid url");

        let parsed = Url::parse(&result).expect("should parse output url");
        assert_eq!(parsed.host_str(), Some("github.com"));
        assert_eq!(parsed.path(), "/login/oauth/authorize");

        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("client_id").map(String::as_str),
            Some("client_123")
        );
        assert_eq!(
            pairs.get("redirect_uri").map(String::as_str),
            Some("https://auth.example.workers.dev/callback")
        );
        assert_eq!(pairs.get("scope").map(String::as_str), Some("repo"));
        assert_eq!(pairs.get("state").map(String::as_str), Some("state-abc"));
    }

    #[test]
    fn extracts_cookie_correctly() {
        let header = "foo=bar; oauth_state=uuid-1234; theme=dark";
        assert_eq!(extract_cookie(header, "oauth_state"), Some("uuid-1234"));
        assert_eq!(extract_cookie(header, "missing"), None);
    }

    #[test]
    fn verifies_oauth_state_securely() {
        assert!(verify_oauth_state(
            Some("abc-123"),
            Some("other=1; oauth_state=abc-123")
        ));
        assert!(!verify_oauth_state(
            Some("abc-123"),
            Some("oauth_state=wrong")
        ));
        assert!(!verify_oauth_state(None, Some("oauth_state=abc-123")));
        assert!(!verify_oauth_state(Some(""), Some("oauth_state=")));
        assert!(!verify_oauth_state(Some("abc-123"), None));
    }

    #[test]
    fn renders_html_with_escaped_payload() {
        let html = render_oauth_html(
            "success",
            &SuccessPayload {
                token: "gho_secret'test",
                provider: "github",
            },
            "https://jorbush.github.io",
        )
        .expect("should render html");

        assert!(html.contains("window.opener.postMessage('authorizing:github', '*')"));
        assert!(html.contains("authorization:github:success:"));
        assert!(html.contains("gho_secret\\'test"));
        assert!(html.contains("const allowedOrigin = \"https://jorbush.github.io\";"));
    }

    #[test]
    fn escapes_closing_script_tags_in_json() {
        let escaped =
            escape_json_for_inline_script(r#"{"error":"</script><img onerror=alert(1)>"}"#);
        assert!(!escaped.contains("</script>"));
        assert!(escaped.contains("\\u003c/script\\u003e"));
    }
}
