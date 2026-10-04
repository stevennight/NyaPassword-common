//! HTTP transport. The default is reqwest (native: rustls with the Mozilla
//! roots; wasm32: the browser's fetch). Tests and special hosts can plug in
//! their own.

use crate::{CoreError, Result};

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: &'static str,
    /// Path and query, starting with `/`.
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<&'static str>,
    pub bearer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse>;
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait Transport: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse>;
}

#[cfg(feature = "http")]
pub struct ReqwestTransport {
    base: String,
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl ReqwestTransport {
    /// `base`: the server URL, e.g. `https://vault.example.com`.
    pub fn new(base: &str) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        if !(base.starts_with("https://")
            || base.starts_with("http://localhost")
            || base.starts_with("http://127.0.0.1")
            || base.starts_with("http://[::1]"))
        {
            return Err(CoreError::Invalid(
                "the server URL must use https (http only for localhost)".into(),
            ));
        }
        #[cfg(not(target_arch = "wasm32"))]
        let client = reqwest::Client::builder()
            .user_agent(concat!("NyaPassword/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| CoreError::Network(e.to_string()))?;
        #[cfg(target_arch = "wasm32")]
        let client = reqwest::Client::new();
        Ok(Self { base, client })
    }
}

#[cfg(feature = "http")]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Transport for ReqwestTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse> {
        let url = format!("{}{}", self.base, req.path);
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| CoreError::Network(e.to_string()))?;
        let mut rb = self.client.request(method, url);
        if let Some(t) = &req.bearer {
            rb = rb.bearer_auth(t);
        }
        if let Some(b) = req.body {
            rb = rb
                .header(
                    "content-type",
                    req.content_type.unwrap_or("application/json"),
                )
                .body(b);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}
