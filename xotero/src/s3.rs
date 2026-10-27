//! S3-compatible object storage for attachment bytes (Cloudflare R2 in
//! production, RustFS in the integration test).
//!
//! Local disk is not used. Uploads are streamed *through* this server: the
//! client POSTs the bytes here, the server verifies the md5, then PUTs the
//! object to the bucket. Downloads are served by redirecting the client to a
//! short-lived pre-signed GET URL, so the bytes are read straight from the
//! bucket and the read path never passes back through this server.

use s3::creds::Credentials;
use s3::{Bucket, Region};

// Re-exported so the crate's binary (whose own `s3` module shadows the extern
// crate name) can name the error type as `s3::S3Error`.
pub use s3::error::S3Error;

/// Connection settings for the bucket. `endpoint`/`region`/`path_style` cover
/// both R2 (`https://<account>.r2.cloudflarestorage.com`, region `auto`) and a
/// local RustFS/MinIO (`http://host:9000`), so the test and production paths use
/// one code path.
#[derive(Clone)]
pub struct Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
    /// Lifetime of a pre-signed download URL, in seconds.
    pub presign_ttl: u32,
}

pub struct Storage {
    bucket: Box<Bucket>,
    presign_ttl: u32,
}

impl Storage {
    pub fn new(cfg: &Config) -> Result<Self, S3Error> {
        let region = Region::Custom {
            region: cfg.region.clone(),
            endpoint: cfg.endpoint.clone(),
        };
        let creds = Credentials::new(
            Some(&cfg.access_key),
            Some(&cfg.secret_key),
            None,
            None,
            None,
        )?;
        let mut bucket = Bucket::new(&cfg.bucket, region, creds)?;
        // RustFS/MinIO need path-style addressing; R2 accepts it too.
        if cfg.path_style {
            bucket = bucket.with_path_style();
        }
        Ok(Storage {
            bucket,
            presign_ttl: cfg.presign_ttl,
        })
    }

    /// Store the object, failing on a non-success status from the backend.
    pub async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), S3Error> {
        let response = self
            .bucket
            .put_object_stream_builder(key)
            .with_content_type(content_type)
            .with_max_concurrent_chunks(2)
            .execute_stream(&mut std::io::Cursor::new(bytes))
            .await?;
        let code = response.status_code();
        if !(200..300).contains(&code) {
            return Err(S3Error::HttpFailWithBody(
                code,
                "object upload did not succeed".into(),
            ));
        }
        Ok(())
    }

    /// Delete an abandoned immutable candidate. S3 deletion is idempotent, so
    /// retrying cleanup after a crash is safe.
    pub async fn delete(&self, key: &str) -> Result<(), S3Error> {
        let response = self.bucket.delete_object(key).await?;
        let code = response.status_code();
        if !(200..300).contains(&code) {
            return Err(S3Error::HttpFailWithBody(
                code,
                String::from_utf8_lossy(response.bytes()).into_owned(),
            ));
        }
        Ok(())
    }

    /// A pre-signed GET URL the client can follow directly to the bucket.
    pub async fn presign_get(&self, key: &str) -> Result<String, S3Error> {
        self.bucket.presign_get(key, self.presign_ttl, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::DefaultBodyLimit;
    use axum::http::{Method, StatusCode, Uri};
    use axum::routing::any;
    use axum::Router;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn put_rejects_malformed_successful_multipart_completion() {
        // Given: a wire-level provider accepts parts but returns truncated XML
        // instead of a successful multipart completion receipt.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let completed = Arc::new(AtomicBool::new(false));
        let completion_receipt = Arc::clone(&completed);
        let provider = Router::new()
            .fallback(any(move |method: Method, uri: Uri, _body: Bytes| {
                let completed = Arc::clone(&completed);
                async move {
                    match (method, uri.query()) {
                        (Method::POST, Some("uploads")) => (
                            StatusCode::OK,
                            [("etag", "\"part\"")],
                            "<InitiateMultipartUploadResult><Bucket>zotero</Bucket>\
                             <Key>large</Key><UploadId>upload</UploadId>\
                             </InitiateMultipartUploadResult>",
                        ),
                        (Method::DELETE, _) => (StatusCode::NO_CONTENT, [("etag", "\"part\"")], ""),
                        (Method::POST, _) => {
                            completed.store(true, Ordering::SeqCst);
                            (
                                StatusCode::OK,
                                [("etag", "\"part\"")],
                                "<Error><Code>InternalError</Code>",
                            )
                        }
                        _ => (
                            StatusCode::OK,
                            [("etag", "\"part\"")],
                            "<Error><Code>InternalError</Code>",
                        ),
                    }
                }
            }))
            .layer(DefaultBodyLimit::disable());
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move { axum::serve(listener, provider).await });
        let storage = Storage::new(&Config {
            endpoint,
            region: "us-east-1".into(),
            bucket: "zotero".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            path_style: true,
            presign_ttl: 120,
        })
        .unwrap();

        // When: actual Storage uploads an object above the SDK part threshold.
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            storage.put("large", &vec![b'x'; 8 * 1024 * 1024 + 1], "text/plain"),
        )
        .await
        .unwrap();

        // Then: HTTP 200 cannot turn malformed completion XML into success.
        servers.abort_all();
        while let Some(result) = servers.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
        assert!(
            result.is_err(),
            "malformed provider completion was accepted"
        );
        assert!(
            completion_receipt.load(Ordering::SeqCst),
            "provider did not observe multipart completion"
        );
    }
}
