//! Typed calls to the server API over a [`Transport`].

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::transport::{HttpRequest, Transport};
use crate::{CoreError, Result};

pub(crate) async fn call<Req: Serialize, Resp: DeserializeOwned>(
    t: &dyn Transport,
    method: &'static str,
    path: &str,
    body: Option<&Req>,
    bearer: Option<&str>,
) -> Result<Resp> {
    let body = match body {
        Some(b) => Some(serde_json::to_vec(b).map_err(|e| CoreError::Invalid(e.to_string()))?),
        None => None,
    };
    let resp = t
        .send(HttpRequest {
            method,
            path: path.to_string(),
            body,
            content_type: Some("application/json"),
            bearer: bearer.map(str::to_string),
        })
        .await?;
    decode(resp.status, &resp.body)
}

pub(crate) async fn call_raw(
    t: &dyn Transport,
    method: &'static str,
    path: &str,
    body: Option<Vec<u8>>,
    bearer: Option<&str>,
) -> Result<Vec<u8>> {
    let resp = t
        .send(HttpRequest {
            method,
            path: path.to_string(),
            body,
            content_type: Some("application/octet-stream"),
            bearer: bearer.map(str::to_string),
        })
        .await?;
    if (200..300).contains(&resp.status) {
        Ok(resp.body)
    } else {
        Err(api_error(resp.status, &resp.body))
    }
}

pub(crate) fn decode<T: DeserializeOwned>(status: u16, body: &[u8]) -> Result<T> {
    if (200..300).contains(&status) {
        let body = if body.is_empty() {
            b"null".as_slice()
        } else {
            body
        };
        serde_json::from_slice(body)
            .map_err(|e| CoreError::Network(format!("unexpected response: {e}")))
    } else {
        Err(api_error(status, body))
    }
}

pub(crate) fn api_error(status: u16, body: &[u8]) -> CoreError {
    match serde_json::from_slice::<npw_api::ApiError>(body) {
        Ok(e) if e.code == npw_api::code::DEVICE_REVOKED => CoreError::DeviceRevoked,
        Ok(e) => CoreError::Api {
            status,
            code: e.code,
            message: e.message,
        },
        Err(_) => CoreError::Api {
            status,
            code: "http".into(),
            message: String::from_utf8_lossy(body).chars().take(200).collect(),
        },
    }
}

pub(crate) fn is_unauthorized(e: &CoreError) -> bool {
    matches!(e, CoreError::Api { status: 401, .. })
}

/// `Empty` request/response body.
#[derive(Serialize, serde::Deserialize, Default)]
pub(crate) struct Empty {}
