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
    pub fn presign_ttl(&self) -> u32 {
        self.presign_ttl
    }

    pub async fn presign_get(&self, key: &str) -> Result<String, S3Error> {
        self.bucket.presign_get(key, self.presign_ttl, None).await
    }

    /// Verify exact stored bytes, never ETag or expanded attachment content.
    /// Only a canonical NoSuchKey response or proven byte mismatch is absence
    /// of valid bytes; provider, framing and transport failures remain errors.
    pub async fn verify_object(
        &self,
        key: &str,
        size: u64,
        md5: &str,
        timeout: std::time::Duration,
    ) -> Result<bool, S3Error> {
        use md5::{Digest, Md5};
        use tokio::io::AsyncReadExt;

        let verify = async {
            let mut response = self.bucket.get_object_stream(key).await?;
            let status = response.status_code;
            if status != 200 {
                if status != 404 {
                    return Err(S3Error::HttpFailWithBody(
                        status,
                        "legacy object verification failed".into(),
                    ));
                }
                // Error documents have a separate fixed cap. Never turn a
                // missing bucket, proxy 404, malformed or truncated XML into
                // permission to publish a different object pointer.
                let mut document = [0u8; 8193];
                let mut length = 0;
                while length < document.len() {
                    let read = response.read(&mut document[length..]).await?;
                    if read == 0 {
                        break;
                    }
                    length += read;
                }
                if length <= 8192 && no_such_key(&document[..length]) {
                    return Ok(false);
                }
                return Err(S3Error::HttpFailWithBody(
                    status,
                    "not a complete NoSuchKey error document".into(),
                ));
            }
            let mut hash = Md5::new();
            let mut read_bytes = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                // At most expected size + 1 bytes are consumed. That extra
                // byte proves mismatch without downloading an oversized blob.
                let remaining = size.saturating_sub(read_bytes).saturating_add(1);
                let limit = usize::try_from(remaining.min(64 * 1024))
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let read = response.read(&mut buffer[..limit]).await?;
                if read == 0 {
                    return Ok(read_bytes == size
                        && format!("{:x}", hash.finalize()).eq_ignore_ascii_case(md5));
                }
                read_bytes = read_bytes
                    .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
                    .ok_or_else(|| std::io::Error::other("object length overflow"))?;
                if read_bytes > size {
                    return Ok(false);
                }
                hash.update(&buffer[..read]);
            }
        };
        tokio::time::timeout(timeout, verify).await.map_err(|_| {
            S3Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "legacy object verification timed out",
            ))
        })?
    }
}

// quick-xml checks markup matching but not XML 1.0's Name productions.
fn xml_name(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let start = |character| {
        matches!(character,
            ':' | 'A'..='Z' | '_' | 'a'..='z'
            | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}' | '\u{f8}'..='\u{2ff}'
            | '\u{370}'..='\u{37d}' | '\u{37f}'..='\u{1fff}'
            | '\u{200c}'..='\u{200d}' | '\u{2070}'..='\u{218f}'
            | '\u{2c00}'..='\u{2fef}' | '\u{3001}'..='\u{d7ff}'
            | '\u{f900}'..='\u{fdcf}' | '\u{fdf0}'..='\u{fffd}'
            | '\u{10000}'..='\u{effff}')
    };
    let mut characters = name.chars();
    characters.next().is_some_and(start)
        && characters.all(|character| {
            start(character)
                || matches!(character,
                    '-' | '.' | '0'..='9' | '\u{b7}'
                    | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}')
        })
}

fn no_such_key(document: &[u8]) -> bool {
    use quick_xml::events::{BytesStart, Event};
    use quick_xml::Reader;

    let Ok(text) = std::str::from_utf8(document) else {
        return false;
    };
    let xml_character = |character| {
        matches!(character, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}'
            | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    };
    if !text.chars().all(xml_character) {
        return false;
    }
    // A declaration cannot follow even otherwise legal prolog whitespace.
    let mut reader = Reader::from_str(text);
    reader.config_mut().enable_all_checks(true);
    let mut depth = 0usize;
    let mut root_seen = false;
    let mut declaration_seen = false;
    let mut code_seen = false;
    let mut in_code = false;
    let mut code = String::new();
    loop {
        let event_start = reader.buffer_position();
        let Ok(event) = reader.read_event() else {
            return false;
        };
        match event {
            Event::Start(ref start) | Event::Empty(ref start) => {
                let empty = matches!(&event, Event::Empty(_));
                if !xml_name(start.name().as_ref()) {
                    return false;
                }
                if start.attributes().any(|attribute| match attribute {
                    Ok(attribute) => {
                        !xml_name(attribute.key.as_ref())
                            || attribute.value.contains(&b'<')
                            || attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Explicit1_0,
                                    reader.decoder(),
                                )
                                .map_or(true, |value| !value.chars().all(xml_character))
                    }
                    Err(_) => true,
                }) {
                    return false;
                }
                if depth == 0 {
                    if root_seen || empty || start.name().as_ref() != b"Error" {
                        return false;
                    }
                    root_seen = true;
                } else if start.name().as_ref() == b"Code" {
                    if depth != 1 || code_seen || empty {
                        return false;
                    }
                    code_seen = true;
                    in_code = true;
                } else if in_code {
                    return false;
                }
                if !empty {
                    depth += 1;
                }
            }
            Event::End(_) => {
                if in_code {
                    in_code = false;
                }
                let Some(parent) = depth.checked_sub(1) else {
                    return false;
                };
                depth = parent;
            }
            Event::Text(value) => {
                let Ok(value) = value.decode() else {
                    return false;
                };
                if value.contains("]]>")
                    || (depth == 0
                        && !value
                            .bytes()
                            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')))
                {
                    return false;
                }
                if in_code {
                    code.push_str(&value);
                }
            }
            Event::GeneralRef(reference) => {
                if depth == 0 || in_code {
                    return false;
                }
                match reference.resolve_char_ref() {
                    Ok(Some(character)) if xml_character(character) => {}
                    Ok(Some(_)) => return false,
                    Ok(None) => {
                        let Ok(name) = reference.decode() else {
                            return false;
                        };
                        if quick_xml::escape::resolve_predefined_entity(&name).is_none() {
                            return false;
                        }
                    }
                    Err(_) => return false,
                }
            }
            Event::Decl(declaration) => {
                if event_start != 0
                    || root_seen
                    || declaration_seen
                    || declaration.version().is_err()
                {
                    return false;
                }
                declaration_seen = true;
                let Ok(content) = std::str::from_utf8(&declaration) else {
                    return false;
                };
                let start = BytesStart::from_content(content, 3);
                let mut previous = 0;
                for attribute in start.attributes() {
                    let Ok(attribute) = attribute else {
                        return false;
                    };
                    let order = match (attribute.key.as_ref(), attribute.value.as_ref()) {
                        (b"version", b"1.0") => 1,
                        (b"encoding", value) if value.eq_ignore_ascii_case(b"utf-8") => 2,
                        (b"standalone", b"yes" | b"no") => 3,
                        _ => return false,
                    };
                    if order <= previous {
                        return false;
                    }
                    previous = order;
                }
            }
            Event::Eof => return root_seen && depth == 0 && code_seen && code == "NoSuchKey",
            Event::CData(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_) => return false,
        }
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
    async fn verification_distinguishes_missing_bytes_from_provider_failures() {
        // Given: actual SDK requests against deterministic provider responses.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let provider = Router::new().fallback(any(move |method: Method, uri: Uri| {
            observed.lock().unwrap().push((method.clone(), uri.clone()));
            async move {
                assert_eq!(method, Method::GET);
                match uri.path() {
                    "/zotero/valid" => (StatusCode::OK, "hello"),
                    "/zotero/wrong" => (StatusCode::OK, "world"),
                    "/zotero/oversized" => (StatusCode::OK, "hello!"),
                    "/zotero/missing" => (
                        StatusCode::NOT_FOUND,
                        "<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code>\
                         <Message>Missing key</Message></Error>",
                    ),
                    "/zotero/bucket" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchBucket</Code></Error>",
                    ),
                    "/zotero/proxy" => (StatusCode::NOT_FOUND, "not found"),
                    "/zotero/truncated" => (StatusCode::NOT_FOUND, "<Error><Code>NoSuchKey</Code>"),
                    "/zotero/malformed" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><Message></Error>",
                    ),
                    "/zotero/declaration" => (
                        StatusCode::NOT_FOUND,
                        "<?xml nonsense?><Error><Code>NoSuchKey</Code></Error>",
                    ),
                    "/zotero/leading-declaration" => (
                        StatusCode::NOT_FOUND,
                        " \n<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>",
                    ),
                    "/zotero/bad-element-start" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><1bad/></Error>",
                    ),
                    "/zotero/bad-element-tail" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><bad!/></Error>",
                    ),
                    "/zotero/bad-attribute-start" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><Message 1bad=\"x\"/></Error>",
                    ),
                    "/zotero/bad-attribute-tail" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><Message bad!=\"x\"/></Error>",
                    ),
                    "/zotero/valid-whitespace" => (
                        StatusCode::NOT_FOUND,
                        " \n<Error><Code>NoSuchKey</Code></Error>\n ",
                    ),
                    "/zotero/valid-unicode-name" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code>\
                         <\u{00c9}l\u{00e9}ment attribut\u{00e9}=\"x\"/></Error>",
                    ),
                    "/zotero/bom-declaration" => (
                        StatusCode::NOT_FOUND,
                        "\u{feff}<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>",
                    ),
                    "/zotero/bad-prolog-whitespace" => (
                        StatusCode::NOT_FOUND,
                        "\u{00a0}<Error><Code>NoSuchKey</Code></Error>",
                    ),
                    "/zotero/bad-text-delimiter" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><Message>]]></Message></Error>",
                    ),
                    "/zotero/duplicate" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code><Code>NoSuchBucket</Code></Error>",
                    ),
                    "/zotero/nested" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Message><Code>NoSuchKey</Code></Message></Error>",
                    ),
                    "/zotero/extra-root" => (
                        StatusCode::NOT_FOUND,
                        "<Error><Code>NoSuchKey</Code></Error><Error></Error>",
                    ),
                    "/zotero/forbidden" => (StatusCode::FORBIDDEN, "denied"),
                    "/zotero/unavailable" => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                    _ => panic!("unexpected request {uri}"),
                }
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
        // When: each exact object is verified by size and actual body MD5.
        let mut violations = Vec::new();
        for (key, expected) in [
            ("valid", Some(true)),
            ("wrong", Some(false)),
            ("oversized", Some(false)),
            ("missing", Some(false)),
            ("bucket", None),
            ("proxy", None),
            ("truncated", None),
            ("malformed", None),
            ("declaration", None),
            ("leading-declaration", None),
            ("bad-element-start", None),
            ("bad-element-tail", None),
            ("bad-attribute-start", None),
            ("bad-attribute-tail", None),
            ("valid-whitespace", Some(false)),
            ("valid-unicode-name", Some(false)),
            ("bom-declaration", Some(false)),
            ("bad-prolog-whitespace", None),
            ("bad-text-delimiter", None),
            ("duplicate", None),
            ("nested", None),
            ("extra-root", None),
            ("forbidden", None),
            ("unavailable", None),
        ] {
            let result = storage
                .verify_object(
                    key,
                    5,
                    "5D41402ABC4B2A76B9719D911017C592",
                    Duration::from_secs(5),
                )
                .await;
            // Then: only missing objects/completed integrity proofs permit
            // considering another key. No mutation or enumeration is issued.
            match expected {
                Some(valid) => {
                    if !matches!(result, Ok(actual) if actual == valid) {
                        violations.push(format!("{key}: {result:?}"));
                    }
                }
                None => {
                    if result.is_ok() {
                        violations.push(format!("{key}: {result:?}"));
                    }
                }
            }
        }
        {
            let observed = requests.lock().unwrap();
            assert_eq!(observed.len(), 24);
            assert!(observed
                .iter()
                .all(|(method, uri)| *method == Method::GET && uri.query().is_none()));
        }
        servers.abort_all();
        while let Some(result) = servers.join_next().await {
            assert!(result.unwrap_err().is_cancelled());
        }
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[tokio::test]
    async fn verification_bounds_reads_and_rejects_truncated_or_stalled_bodies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for (length, body, hold, mismatch) in [
            (1_048_576, "hello!", true, true),
            (5, "he", false, false),
            (5, "he", true, false),
        ] {
            // Given: real wire framing, including unfinished response bodies.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (sent, received) = tokio::sync::oneshot::channel();
            let (release, held) = tokio::sync::oneshot::channel();
            let mut servers = tokio::task::JoinSet::new();
            servers.spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0);
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() <= 8192);
                }
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\
                             Connection: close\r\n\r\n{body}"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                sent.send(()).unwrap();
                if hold {
                    held.await.unwrap();
                }
            });
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
            // When: verifying size five without waiting for oversized EOF.
            let verification = storage.verify_object(
                "wire",
                5,
                "5d41402abc4b2a76b9719d911017c592",
                Duration::from_secs(1),
            );
            let (result, ()) = tokio::join!(verification, async {
                tokio::time::timeout(Duration::from_secs(5), received)
                    .await
                    .unwrap()
                    .unwrap();
            });
            // Then: size+1 proves mismatch, but truncated framing and a
            // response deadline are provider errors, never missing objects.
            if mismatch {
                assert!(!result.unwrap());
            } else {
                assert!(result.is_err(), "{result:?}");
            }
            if hold {
                release.send(()).unwrap();
            }
            while let Some(result) = servers.join_next().await {
                result.unwrap();
            }
        }
    }

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
