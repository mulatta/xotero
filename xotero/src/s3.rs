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
    pub async fn put<R: tokio::io::AsyncRead + Unpin + Send + ?Sized>(
        &self,
        key: &str,
        reader: &mut R,
        content_type: &str,
        parts: usize,
    ) -> Result<(), S3Error> {
        let response = self
            .bucket
            .put_object_stream_builder(key)
            .with_content_type(content_type)
            .with_max_concurrent_chunks(parts)
            .execute_stream(reader)
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
        // Page API retains HTTP status; the SDK aggregate listing discards it.
        // Prefix is discovery only: full returned key equality grants abort.
        let mut key_marker = None;
        let mut upload_marker = None;
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert((key_marker.clone(), upload_marker.clone())) {
                return Err(S3Error::InvalidMultipartUploadsPagination(
                    "pagination cursor repeated",
                ));
            }
            let (page, status) = self
                .bucket
                .list_multiparts_uploads_page(Some(key), None, key_marker, upload_marker, Some(32))
                .await?;
            if !(200..300).contains(&status) {
                return Err(S3Error::HttpFailWithBody(
                    status,
                    "multipart listing failed".into(),
                ));
            }
            for upload in page.uploads {
                if upload.key == key {
                    self.bucket.abort_upload(key, &upload.id).await?;
                }
            }
            if !page.is_truncated {
                break;
            }
            key_marker = Some(page.next_marker.ok_or(
                S3Error::InvalidMultipartUploadsPagination(
                    "truncated response has no next key marker",
                ),
            )?);
            upload_marker = page.next_upload_id_marker;
        }
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
    async fn stream_backpressure_bounds_source_and_dropped_future_needs_cleanup() {
        use axum::body::Body;
        use futures_util::stream;
        use md5::{Digest, Md5};
        use std::sync::atomic::AtomicUsize;

        // Given: actual SDK wire requests, with both part completions withheld.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let barrier = Arc::new(tokio::sync::Semaphore::new(0));
        let held = Arc::clone(&barrier);
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let source = Arc::new(AtomicUsize::new(0));
        let advanced = Arc::clone(&source);
        let provider = Router::new().fallback(any(move |method: Method, uri: Uri, _body: Bytes| {
            let barrier = Arc::clone(&held);
            let events = events.clone();
            async move {
                if method == Method::PUT {
                    events.send("part").unwrap();
                    let _permit = barrier.acquire().await.unwrap();
                    return (StatusCode::OK, [("etag", "\"part\"")], "");
                }
                if method == Method::POST && uri.query() == Some("uploads") {
                    return (StatusCode::OK, [("etag", "\"part\"")],
                        "<InitiateMultipartUploadResult><Bucket>zotero</Bucket>\
                         <Key>candidate</Key><UploadId>owned</UploadId>\
                         </InitiateMultipartUploadResult>");
                }
                if method == Method::GET {
                    return (StatusCode::OK, [("etag", "\"part\"")],
                        "<ListMultipartUploadsResult><Bucket>zotero</Bucket>\
                         <IsTruncated>false</IsTruncated>\
                         <Upload><Key>candidate</Key><UploadId>owned</UploadId>\
                         <Initiated>2026-10-27T00:00:00Z</Initiated><StorageClass>STANDARD</StorageClass></Upload>\
                         </ListMultipartUploadsResult>");
                }
                events.send(if uri.query().is_some() { "abort" } else { "delete" }).unwrap();
                (StatusCode::NO_CONTENT, [("etag", "\"part\"")], "")
            }
        })).layer(DefaultBodyLimit::disable());
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move { axum::serve(listener, provider).await });
        let storage = Arc::new(
            Storage::new(&Config {
                endpoint,
                region: "us-east-1".into(),
                bucket: "zotero".into(),
                access_key: "test".into(),
                secret_key: "test".into(),
                path_style: true,
                presign_ttl: 120,
            })
            .unwrap(),
        );
        let bytes = Bytes::from(vec![b'x'; 64 * 1024]);
        let body = Body::from_stream(stream::poll_fn(move |_| {
            if advanced.load(Ordering::SeqCst) == 32 * 1024 * 1024 {
                return std::task::Poll::Ready(None);
            }
            advanced.fetch_add(bytes.len(), Ordering::SeqCst);
            std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(bytes.clone())))
        }));
        let mut hash = Md5::new();
        for _ in 0..512 {
            hash.update([b'x'; 64 * 1024]);
        }
        let mut reader = crate::upload::attachment_reader(
            body,
            &axum::http::HeaderMap::new(),
            32 * 1024 * 1024,
            32 * 1024 * 1024,
            format!("{:x}", hash.finalize()),
        )
        .unwrap();
        let uploader = Arc::clone(&storage);
        let task = tokio::spawn(async move {
            uploader
                .put("candidate", &mut reader, "application/octet-stream", 2)
                .await
        });

        // When: the backend has both requests and neither may complete.
        for _ in 0..2 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(10), observed.recv())
                    .await
                    .unwrap(),
                Some("part")
            );
        }
        // Then: SDK has consumed exactly two 8 MiB chunks, not the 32 MiB source.
        assert_eq!(source.load(Ordering::SeqCst), 16 * 1024 * 1024);
        assert!(observed.try_recv().is_err());
        println!("STREAM_BOUND source_bytes={} inflight_parts=2 configured_parts=2 source_total=33554432", source.load(Ordering::SeqCst));

        // When: dropping the actual SDK future while multipart requests are held.
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        // Then: SDK cannot asynchronously abort on drop; durable cleanup must.
        assert!(observed.try_recv().is_err());
        tokio::time::timeout(Duration::from_secs(10), storage.delete("candidate"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.try_recv().unwrap(), "abort");
        assert_eq!(observed.try_recv().unwrap(), "delete");
        println!("SDK_DROP no_implicit_abort=true explicit_exact_abort=true");
        barrier.add_permits(2);
        servers.abort_all();
        while let Some(result) = servers.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    async fn candidate_cleanup_aborts_only_exact_recorded_key() {
        // Given: a provider returns both an exact candidate and a prefix neighbor.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&events);
        let provider = Router::new().fallback(any(move |method: Method, uri: Uri| {
            let events = Arc::clone(&observed);
            async move {
                events.lock().unwrap().push(format!("{method} {uri}"));
                if method == Method::GET {
                    return (StatusCode::OK,
                        "<ListMultipartUploadsResult><Bucket>zotero</Bucket>\
                         <IsTruncated>false</IsTruncated>\
                         <Upload><Key>candidate</Key><UploadId>owned</UploadId>\
                         <Initiated>2026-10-27T00:00:00Z</Initiated><StorageClass>STANDARD</StorageClass></Upload>\
                         <Upload><Key>candidate-neighbor</Key><UploadId>unrelated</UploadId>\
                         <Initiated>2026-10-27T00:00:00Z</Initiated><StorageClass>STANDARD</StorageClass></Upload>\
                         </ListMultipartUploadsResult>");
                }
                (StatusCode::NO_CONTENT, "")
            }
        }));
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

        // When: durable pending-candidate cleanup runs.
        tokio::time::timeout(Duration::from_secs(10), storage.delete("candidate"))
            .await
            .unwrap()
            .unwrap();

        // Then: exact prefix discovery precedes owned abort and object deletion.
        let events = events.lock().unwrap().clone();
        assert_eq!(events.len(), 3, "{events:?}");
        assert!(events[0].starts_with("GET /zotero/"), "{events:?}");
        assert!(events[0].contains("prefix=candidate"), "{events:?}");
        assert_eq!(events[1], "DELETE /zotero/candidate?uploadId=owned");
        assert_eq!(events[2], "DELETE /zotero/candidate");
        servers.abort_all();
        while let Some(result) = servers.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    async fn candidate_cleanup_checks_page_status_and_cursor_progress() {
        let terminal = "<ListMultipartUploadsResult><Bucket>zotero</Bucket>\
                        <IsTruncated>false</IsTruncated></ListMultipartUploadsResult>";
        let continued = "<ListMultipartUploadsResult><Bucket>zotero</Bucket>\
                         <IsTruncated>true</IsTruncated><NextKeyMarker>candidate</NextKeyMarker>\
                         <NextUploadIdMarker>cursor</NextUploadIdMarker></ListMultipartUploadsResult>";
        let missing = "<ListMultipartUploadsResult><Bucket>zotero</Bucket>\
                       <IsTruncated>true</IsTruncated></ListMultipartUploadsResult>";
        for (pages, expected_status, expected_gets) in [
            (vec![(200, continued), (200, terminal)], None, 2),
            (vec![(503, terminal)], Some(503), 1),
            (vec![(200, missing)], Some(0), 1),
            (vec![(200, continued), (200, continued)], Some(0), 2),
        ] {
            // Given: real SDK parsing of a provider's paginated wire replies.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let pages = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(
                pages,
            )));
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = Arc::clone(&requests);
            let provider = Router::new().fallback(any(move |method: Method, uri: Uri| {
                let requests = Arc::clone(&observed);
                let pages = Arc::clone(&pages);
                async move {
                    requests.lock().unwrap().push((method.clone(), uri));
                    if method == Method::GET {
                        let (status, body) = pages.lock().unwrap().pop_front().unwrap();
                        return (StatusCode::from_u16(status).unwrap(), body);
                    }
                    (StatusCode::NO_CONTENT, "")
                }
            }));
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

            // When: one exact candidate cleanup traverses the response pages.
            let result = tokio::time::timeout(Duration::from_secs(10), storage.delete("candidate"))
                .await
                .unwrap();

            // Then: only complete successful discovery permits object deletion.
            match expected_status {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(503) => assert!(matches!(result, Err(S3Error::HttpFailWithBody(503, _)))),
                Some(_) => assert!(matches!(
                    result,
                    Err(S3Error::InvalidMultipartUploadsPagination(_))
                )),
            }
            let requests = requests.lock().unwrap().clone();
            let gets: Vec<_> = requests
                .iter()
                .filter(|(method, _)| *method == Method::GET)
                .collect();
            assert_eq!(gets.len(), expected_gets);
            for (_, uri) in &gets {
                assert!(uri.query().unwrap().contains("prefix=candidate"));
                assert!(uri.query().unwrap().contains("max-uploads=32"));
            }
            if expected_gets == 2 {
                assert!(gets[1].1.query().unwrap().contains("key-marker=candidate"));
                assert!(gets[1]
                    .1
                    .query()
                    .unwrap()
                    .contains("upload-id-marker=cursor"));
            }
            assert_eq!(
                requests
                    .iter()
                    .filter(|(method, _)| *method == Method::DELETE)
                    .count(),
                usize::from(expected_status.is_none())
            );
            servers.abort_all();
            while let Some(result) = servers.join_next().await {
                assert!(result.unwrap_err().is_cancelled());
            }
        }
    }

    #[tokio::test]
    async fn put_rejects_malformed_successful_multipart_completion() {
        // Given: a wire-level provider accepts parts but returns truncated XML
        // instead of a successful multipart completion receipt.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let completed = Arc::new(AtomicBool::new(false));
        let aborted = Arc::new(AtomicBool::new(false));
        let completion_receipt = Arc::clone(&completed);
        let abort_receipt = Arc::clone(&aborted);
        let provider = Router::new()
            .fallback(any(move |method: Method, uri: Uri, _body: Bytes| {
                let completed = Arc::clone(&completed);
                let aborted = Arc::clone(&aborted);
                async move {
                    match (method, uri.query()) {
                        (Method::POST, Some("uploads")) => (
                            StatusCode::OK,
                            [("etag", "\"part\"")],
                            "<InitiateMultipartUploadResult><Bucket>zotero</Bucket>\
                             <Key>large</Key><UploadId>upload</UploadId>\
                             </InitiateMultipartUploadResult>",
                        ),
                        (Method::DELETE, _) => {
                            aborted.store(true, Ordering::SeqCst);
                            (StatusCode::NO_CONTENT, [("etag", "\"part\"")], "")
                        }
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
            storage.put(
                "large",
                &mut std::io::Cursor::new(vec![b'x'; 8 * 1024 * 1024 + 1]),
                "text/plain",
                2,
            ),
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
        assert!(
            abort_receipt.load(Ordering::SeqCst),
            "SDK error returned without abort"
        );
        println!("SDK_ERROR automatic_abort_before_return=true");
    }
}
