
use std::{collections::HashMap, env};
use std::net::SocketAddr;
use std::str::FromStr;

use url::Url;

use axum::{
    routing::get,
    Router,
    response::Response,
    middleware::Next, body::Body,
};

use axum::{
    response::IntoResponse,
    extract::Query,
};

use axum::http::{
    Request,
    StatusCode,
    HeaderMap,
    HeaderName,
};

use base64::prelude::*;


use ed25519_dalek::{Verifier, VerifyingKey};

use serenity::model::id::ChannelId;


static RESPONSE_HEADER_CSP: &str = "default-src https:; base-uri 'none'; form-action https:; frame-ancestors 'none';";
static RESPONSE_HEADER_X_FRAME_OPTIONS: &str = "DENY";
static RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS: &str = "nosniff";


/// Middleware to add global headers to all responses.
async fn add_global_headers(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.append("content-security-policy", RESPONSE_HEADER_CSP.parse().unwrap());
    headers.append("x-frame-options", RESPONSE_HEADER_X_FRAME_OPTIONS.parse().unwrap());
    headers.append("x-content-type-options", RESPONSE_HEADER_X_CONTENT_TYPE_OPTIONS.parse().unwrap());
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

    let callback_url = Url::parse(&server_url).unwrap().join("/invite/invited").unwrap().to_string();

    let mut captcha_url = Url::parse(&captcha_url).unwrap();
    captcha_url.query_pairs_mut().append_pair("redirect-url", &callback_url);
    captcha_url.query_pairs_mut().append_pair("request-token", &token);

    let captcha_url: String = captcha_url.into();

    let mut header_map = HeaderMap::new();
    header_map.insert(HeaderName::from_static("location"), captcha_url.parse().unwrap());

    (
        StatusCode::SEE_OTHER,
        header_map,
        "Redirecting...",
    ).into_response()
}

async fn handler_invited(
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let discord_token = env::var("DISCORD_TOKEN").unwrap_or("".to_string());
    let discord_channel_id = env::var("DISCORD_CHANNEL_ID").unwrap_or("".to_string());
    let captcha_server_public_key = env::var("CAPTCHA_SERVER_PUBLIC_KEY").unwrap_or("".to_string());

    let public_key = VerifyingKey::from_bytes(base64::prelude::BASE64_STANDARD.decode(captcha_server_public_key.trim()).unwrap()[0..32].try_into().unwrap()).unwrap();

    let request_token = if let Some(token) = query.get("request-token") {
        token
    } else {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    };

    let signature = if let Some(signature) = query.get("signature") {
        signature
    } else {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    };

    let signature = if let Ok(signature) = hex::decode(signature) {
        signature
    } else {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    };

    let signature = signature[0..64].try_into() as Result<[u8; 64], _>;

    let signature = match signature {
        Ok(signature) => signature,
        Err(_) => return (StatusCode::BAD_REQUEST, "Bad Request").into_response(),
    };

    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    if !public_key.verify(request_token.as_bytes(), &signature).is_ok() {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    }

    let request_token = if let Ok(token) = hex::decode(request_token) {
        token
    } else {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    };

    let request_token = request_token[0..8].try_into() as Result<[u8; 8], _>;
    let request_token = match request_token {
        Ok(token) => token,
        Err(_) => return (StatusCode::BAD_REQUEST, "Bad Request").into_response(),
    };

    let request_token = u64::from_be_bytes(request_token);
    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();

    if request_token < now || request_token > now + 60 * 5 {
        return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
    }

    // should include just one IP address and port
    let real_ip = headers.get("x-real-ip").map(|value| value.to_str().unwrap().to_string());
    let user_agent = headers.get("user-agent").map(|value| value.to_str().unwrap().to_string());

    let discord_webhook_url = env::var("DISCORD_WEBHOOK_URL").unwrap_or("".to_string());

    let discord_webhook_body = serde_json::json!({
        "content": "Someone has passed the captcha!",
        "embeds": [
            {
                "title": "Captcha Passed",
                "description": "Someone has passed the captcha to join Discord server!",
                "fields": [
                    {
                        "name": "IP Address",
                        "value": real_ip.unwrap_or("Unknown".to_string()),
                        "inline": true
                    },
                    {
                        "name": "User Agent",
                        "value": user_agent.unwrap_or("Unknown".to_string()),
                        "inline": true
                    }
                ],
                "color": 0x00FF00
            }
        ]
    });

    let http_client = reqwest::Client::new();
    let result = http_client.post(&discord_webhook_url)
        .json(&discord_webhook_body)
        .send()
        .await;

    if let Err(e) = result {
        eprintln!("Failed to send webhook: {:?}", e);
    }

    let discord_channel_id = ChannelId::new(discord_channel_id.parse().unwrap());

    let http_client = serenity::http::Http::new(&discord_token);
    let reason = Some("Invited by captcha");
    let invite = http_client.create_invite(discord_channel_id, &serde_json::json!({
        "max_age": 600,
        "max_uses": 1,
        "unique": true,
    }), reason).await;

    let invite = match invite {
        Ok(invite) => invite.url(),
        Err(e) => {
            eprintln!("Failed to create invite: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response();
        }
    };
    
    let mut header_map = HeaderMap::new();
    header_map.insert(HeaderName::from_static("location"), invite.parse().unwrap());

    (
        StatusCode::SEE_OTHER,
        header_map,
        "Redirecting...",
    ).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;

    // bind address
    let addr_string = env::var("LISTEN_ADDR").unwrap_or("".to_string());
    let addr = SocketAddr::from_str(&addr_string).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 7880)));

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

    println!("Listening on http://{}", &addr);

    server.await?;

    Ok(())
}
