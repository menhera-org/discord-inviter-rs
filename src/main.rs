use std::net::SocketAddr;
use std::str::FromStr;
use std::{collections::HashMap, env};

use url::Url;

use axum::{body::Body, middleware::Next, response::Response, routing::get, Router};

use axum::{extract::Query, response::IntoResponse};

use axum::http::{HeaderMap, HeaderName, Request, StatusCode};

use base64::prelude::*;

use ed25519_dalek::{Verifier, VerifyingKey};

use serenity::model::id::ChannelId;

static RESPONSE_HEADER_CSP: &str =
    "default-src https:; base-uri 'none'; form-action https:; frame-ancestors 'none';";
static RESPONSE_HEADER_X_FRAME_OPTIONS: &str = "DENY";
static RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS: &str = "nosniff";

/// Middleware to add global headers to all responses.
async fn add_global_headers(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.append(
        "content-security-policy",
        RESPONSE_HEADER_CSP.parse().unwrap(),
    );
    headers.append(
        "x-frame-options",
        RESPONSE_HEADER_X_FRAME_OPTIONS.parse().unwrap(),
    );
    headers.append(
        "x-content-type-options",
        RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS.parse().unwrap(),
    );
    res
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "404 Not Found").into_response()
}

async fn handler_root() -> impl IntoResponse {
    let server_url = env::var("SERVER_URL").unwrap_or("".to_string());
    let captcha_url = env::var("CAPTCHA_URL").unwrap_or("".to_string());

    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let expires = now + 60 * 5;
    let token = hex::encode(expires.to_be_bytes());

    let callback_url = Url::parse(&server_url)
        .unwrap()
        .join("/invite/invited")
        .unwrap()
        .to_string();

    let mut captcha_url = Url::parse(&captcha_url).unwrap();
    captcha_url
        .query_pairs_mut()
        .append_pair("redirect-url", &callback_url);
    captcha_url
        .query_pairs_mut()
        .append_pair("request-token", &token);

    let captcha_url: String = captcha_url.into();

    let mut header_map = HeaderMap::new();
    header_map.insert(
        HeaderName::from_static("location"),
        captcha_url.parse().unwrap(),
    );

    (StatusCode::SEE_OTHER, header_map, "Redirecting...").into_response()
}

fn validate_request_token(
    public_key: &VerifyingKey,
    request_token: &str,
    signature: &str,
    now: u64,
) -> Result<(), &'static str> {
    let signature = hex::decode(signature).map_err(|_| "Invalid signature encoding")?;
    let signature =
        ed25519_dalek::Signature::from_slice(&signature).map_err(|_| "Invalid signature length")?;

    public_key
        .verify(request_token.as_bytes(), &signature)
        .map_err(|_| "Invalid signature from CAPTCHA server")?;

    let request_token = hex::decode(request_token).map_err(|_| "Invalid token")?;
    let request_token: [u8; 8] = request_token
        .try_into()
        .map_err(|_| "Invalid token length")?;
    let request_token = u64::from_be_bytes(request_token);

    if request_token < now || request_token > now + 60 * 5 {
        return Err("Token expired");
    }

    Ok(())
}

async fn handler_invited(
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let discord_token = env::var("DISCORD_TOKEN").unwrap_or("".to_string());
    let discord_channel_id = env::var("DISCORD_CHANNEL_ID").unwrap_or("".to_string());
    let captcha_server_public_key = env::var("CAPTCHA_SERVER_PUBLIC_KEY").unwrap_or("".to_string());

    let public_key = VerifyingKey::from_bytes(
        base64::prelude::BASE64_STANDARD
            .decode(captcha_server_public_key.trim())
            .unwrap()[0..32]
            .try_into()
            .unwrap(),
    )
    .unwrap();

    let request_token = if let Some(token) = query.get("request-token") {
        token
    } else {
        return (StatusCode::BAD_REQUEST, "Bad Request: request token").into_response();
    };

    let signature = if let Some(signature) = query.get("signature") {
        signature
    } else {
        return (StatusCode::BAD_REQUEST, "Bad Request: missing signature").into_response();
    };

    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    if let Err(message) = validate_request_token(&public_key, request_token, signature, now) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }

    // should include just one IP address and port
    let real_ip = headers
        .get("x-real-ip")
        .map(|value| value.to_str().unwrap().trim().to_string());
    let user_agent = headers
        .get("user-agent")
        .map(|value| value.to_str().unwrap().to_string());

    // fix broken IPv6 address (address:port, without [])
    let real_ip = real_ip
        .map(|ip| {
            let ip_clone = ip.clone();
            let mut parts = ip.split(':').collect::<Vec<_>>();
            if parts.len() == 1 {
                return parts[0].to_string();
            }
            let port: u16 = parts.pop().unwrap().parse().unwrap_or(0);
            if port == 0 {
                return ip_clone;
            }
            let ip = parts.join(":");
            let ip = ip.parse::<std::net::IpAddr>();
            let ip = if let Ok(ip) = ip {
                ip
            } else {
                return ip_clone;
            };
            let socket_addr = std::net::SocketAddr::new(ip, port);
            socket_addr.to_string()
        })
        .filter(|ip| ip.parse::<std::net::SocketAddr>().is_ok());

    let discord_channel_id = ChannelId::new(discord_channel_id.parse().unwrap());

    let http_client = serenity::http::Http::new(&discord_token);
    let reason = Some("Invited by captcha");
    let invite = http_client
        .create_invite(
            discord_channel_id,
            &serde_json::json!({
                "max_age": 600,
                "max_uses": 1,
                "unique": true,
            }),
            reason,
        )
        .await;

    let invite = match invite {
        Ok(invite) => invite,
        Err(e) => {
            eprintln!("Failed to create invite: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response();
        }
    };

    let discord_webhook_url = env::var("DISCORD_WEBHOOK_URL").unwrap_or("".to_string());

    let discord_webhook_body = serde_json::json!({
        "content": "Someone has passed the captcha!",
        "embeds": [
            {
                "title": "Captcha Passed",
                "description": "Someone has passed the captcha to join Discord server!",
                "fields": [
                    {
                        "name": "IP Address and Port",
                        "value": real_ip.unwrap_or("Unknown".to_string()),
                        "inline": true
                    },
                    {
                        "name": "User Agent",
                        "value": user_agent.unwrap_or("Unknown".to_string()),
                        "inline": true
                    },
                    {
                        "name": "Associated Invite Code",
                        "value": invite.code.clone(),
                        "inline": false
                    }
                ],
                "color": 0x00FF00
            }
        ]
    });

    let http_client = reqwest::Client::new();
    let result = http_client
        .post(&discord_webhook_url)
        .json(&discord_webhook_body)
        .send()
        .await;

    if let Err(e) = result {
        eprintln!("Failed to send webhook: {:?}", e);
    }

    let invite = invite.url();
    let mut header_map = HeaderMap::new();
    header_map.insert(HeaderName::from_static("location"), invite.parse().unwrap());

    (StatusCode::SEE_OTHER, header_map, "Redirecting...").into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;

    // bind address
    let addr_string = env::var("LISTEN_ADDR").unwrap_or("".to_string());
    let addr =
        SocketAddr::from_str(&addr_string).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 7880)));

    // define routes
    let app = Router::new()
        // top page
        .route("/invite/", get(handler_root))
        .route("/invite/invited", get(handler_invited))
        // 404 page
        .fallback(handler_404)
        // add global headers
        .layer(axum::middleware::from_fn(add_global_headers));

    // run server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let server = axum::serve(listener, app);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_800_000_000;

    fn validate_signed_token(token: &str) -> Result<(), &'static str> {
        let key = SigningKey::from_bytes(&[42; 32]);
        let signature = hex::encode(key.sign(token.as_bytes()).to_bytes());
        validate_request_token(&key.verifying_key(), token, &signature, NOW)
    }

    #[test]
    fn accepts_valid_tokens_through_the_expiration_boundary() {
        for expiration in [NOW, NOW + 1, NOW + 300] {
            let token = hex::encode(expiration.to_be_bytes());
            assert_eq!(validate_signed_token(&token), Ok(()));
        }
    }

    #[test]
    fn rejects_expired_and_excessively_future_tokens() {
        for expiration in [NOW - 1, NOW + 301] {
            let token = hex::encode(expiration.to_be_bytes());
            assert_eq!(validate_signed_token(&token), Err("Token expired"));
        }
    }

    #[test]
    fn rejects_malformed_signed_tokens() {
        assert_eq!(validate_signed_token("not hex"), Err("Invalid token"));
        for length in [0, 7, 9] {
            let token = hex::encode(vec![0; length]);
            assert_eq!(validate_signed_token(&token), Err("Invalid token length"));
        }
    }

    #[test]
    fn rejects_malformed_signatures_without_panicking() {
        let key = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let token = hex::encode((NOW + 300).to_be_bytes());
        assert_eq!(
            validate_request_token(&key, &token, "not hex", NOW),
            Err("Invalid signature encoding")
        );
        for length in [0, 63, 65] {
            let signature = hex::encode(vec![0; length]);
            assert_eq!(
                validate_request_token(&key, &token, &signature, NOW),
                Err("Invalid signature length")
            );
        }
    }

    #[test]
    fn rejects_tampered_tokens_and_signatures_from_another_key() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let token = hex::encode((NOW + 300).to_be_bytes());
        let signature = hex::encode(key.sign(token.as_bytes()).to_bytes());
        let other_token = hex::encode((NOW + 299).to_be_bytes());
        let other_key = SigningKey::from_bytes(&[43; 32]);
        for (public_key, token) in [
            (key.verifying_key(), other_token),
            (other_key.verifying_key(), token),
        ] {
            assert_eq!(
                validate_request_token(&public_key, &token, &signature, NOW),
                Err("Invalid signature from CAPTCHA server")
            );
        }
    }

    #[tokio::test]
    async fn upgraded_http_clients_create_invites_and_send_webhooks() {
        let app = Router::new()
            .route(
                "/api/v10/channels/123/invites",
                axum::routing::post(
                    |headers: HeaderMap, axum::Json(body): axum::Json<serde_json::Value>| async move {
                        assert_eq!(headers["authorization"], "Bot test-token");
                        assert_eq!(headers["x-audit-log-reason"], "Invited%20by%20captcha");
                        assert_eq!(body, serde_json::json!({
                            "max_age": 600, "max_uses": 1, "unique": true,
                        }));
                        axum::Json(serde_json::json!({
                            "code": "test-invite",
                            "channel": { "id": "123", "name": "test", "type": 0 },
                            "created_at": "2026-10-25T00:00:00Z",
                            "max_age": 600,
                            "max_uses": 1,
                            "temporary": false,
                            "uses": 0,
                        }))
                    },
                ),
            )
            .route(
                "/webhook",
                axum::routing::post(
                    |axum::Json(body): axum::Json<serde_json::Value>| async move {
                        assert_eq!(body["content"], "Someone has passed the captcha!");
                        StatusCode::NO_CONTENT
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let discord = serenity::http::HttpBuilder::new("test-token")
            .client(client.clone())
            .proxy(&base_url)
            .ratelimiter_disabled(true)
            .build();

        let invite = discord
            .create_invite(
                ChannelId::new(123),
                &serde_json::json!({ "max_age": 600, "max_uses": 1, "unique": true }),
                Some("Invited by captcha"),
            )
            .await
            .unwrap();
        assert_eq!(invite.url(), "https://discord.gg/test-invite");
        let response = client
            .post(format!("{base_url}/webhook"))
            .json(&serde_json::json!({ "content": "Someone has passed the captcha!" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        server.abort();
    }
}
