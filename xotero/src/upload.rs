use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};

use async_compression::tokio::bufread::GzipDecoder;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use futures_util::{Stream, TryStreamExt};
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, BufReader, ReadBuf};
use tokio_util::io::StreamReader;

const READ_WINDOW: usize = 64 * 1024;
// Pinned Hyper HTTP/1 read buffers stay below 1 MiB. Reject non-transport
// adversarial frames before StreamReader can retain them, and copy accepted
// frames so a small Bytes slice cannot hide an arbitrarily large backing owner.
const MAX_FRAME: usize = 1024 * 1024;

pub(crate) fn observed_body(body: Body) -> (Body, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&polls);
    let mut source = body.into_data_stream();
    let body = Body::from_stream(futures_util::stream::poll_fn(move |cx| {
        observed.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut source).poll_next(cx)
    }));
    (body, polls)
}

pub(crate) async fn admit(
    uploads: Arc<tokio::sync::Semaphore>,
    polls: &AtomicUsize,
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError> {
    let acquire = uploads.acquire_owned();
    tokio::pin!(acquire);
    let mut reported = false;
    std::future::poll_fn(|cx| match acquire.as_mut().poll(cx) {
        Poll::Pending => {
            if !reported {
                tracing::info!(
                    upload_admission_blocked = true,
                    upload_body_polls = polls.load(Ordering::SeqCst),
                    "upload admission blocked"
                );
                reported = true;
            }
            Poll::Pending
        }
        result => result,
    })
    .await
}

/// Both encoded transport and decoded attachment bytes have independent limits.
/// Validation happens at EOF, before the SDK can complete the object.
pub(crate) struct Reader<R> {
    inner: R,
    limit: u64,
    expected: Option<(u64, String)>,
    hash: Md5,
    pub(crate) bytes: u64,
    pub(crate) error: Option<StatusCode>,
}

impl<R> Reader<R> {
    fn new(inner: R, limit: u64, expected: Option<(u64, String)>) -> Self {
        Self {
            inner,
            limit,
            expected,
            hash: Md5::new(),
            bytes: 0,
            error: None,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining = this
            .expected
            .as_ref()
            .map_or(this.limit, |(size, _)| this.limit.min(*size))
            .saturating_sub(this.bytes)
            .saturating_add(1);
        let capacity = output
            .remaining()
            .min(READ_WINDOW)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut chunk = ReadBuf::new(output.initialize_unfilled_to(capacity));
        match Pin::new(&mut this.inner).poll_read(cx, &mut chunk) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.error = Some(if error.kind() == io::ErrorKind::FileTooLarge {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                });
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(())) => {}
        }
        let bytes = chunk.filled();
        let length = bytes.len();
        this.bytes += u64::try_from(length).expect("read window fits u64");
        if this.bytes > this.limit {
            this.error = Some(StatusCode::PAYLOAD_TOO_LARGE);
            return Poll::Ready(Err(io::ErrorKind::FileTooLarge.into()));
        }
        if let Some((size, hash)) = &this.expected {
            this.hash.update(bytes);
            if this.bytes > *size
                || (length == 0
                    && (this.bytes != *size
                        || !format!("{:x}", this.hash.clone().finalize())
                            .eq_ignore_ascii_case(hash)))
            {
                this.error = Some(StatusCode::BAD_REQUEST);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "uploaded bytes do not match md5/filesize",
                )));
            }
        }
        output.advance(length);
        Poll::Ready(Ok(()))
    }
}

pub(crate) type AttachmentReader = Reader<Box<dyn AsyncRead + Unpin + Send>>;

pub(crate) fn attachment_reader(
    body: Body,
    headers: &HeaderMap,
    limit: u64,
    size: u64,
    hash: String,
) -> Result<AttachmentReader, StatusCode> {
    let raw = StreamReader::new(body.into_data_stream().map_err(io::Error::other).and_then(
        |frame| {
            futures_util::future::ready(if frame.len() > MAX_FRAME {
                Err(io::ErrorKind::FileTooLarge.into())
            } else {
                Ok(axum::body::Bytes::copy_from_slice(&frame))
            })
        },
    ));
    let raw = Reader::new(raw, limit, None);
    let inner: Box<dyn AsyncRead + Unpin + Send> = match headers.get("content-encoding") {
        None => Box::new(raw),
        Some(value) if value.as_bytes().eq_ignore_ascii_case(b"identity") => Box::new(raw),
        Some(value) if value.as_bytes().eq_ignore_ascii_case(b"gzip") => {
            let mut decoder = GzipDecoder::new(BufReader::with_capacity(READ_WINDOW, raw));
            decoder.multiple_members(true);
            Box::new(decoder)
        }
        Some(_) => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    };
    Ok(Reader::new(inner, limit, Some((size, hash))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn fifth_admission_returns_pending_without_polling_body() {
        // Given: four actual admissions own every permit.
        let uploads = Arc::new(tokio::sync::Semaphore::new(4));
        let mut permits = Vec::new();
        for _ in 0..4 {
            permits.push(uploads.clone().acquire_owned().await.unwrap());
        }
        let (body, polls) = observed_body(Body::from("hello"));
        let observed = Arc::clone(&polls);
        let mut fifth = Box::pin(async move {
            let _permit = admit(uploads, &polls).await.unwrap();
            let mut reader = attachment_reader(
                body,
                &HeaderMap::new(),
                5,
                5,
                "5d41402abc4b2a76b9719d911017c592".into(),
            )
            .unwrap();
            let mut result = Vec::new();
            reader.read_to_end(&mut result).await.unwrap();
            result
        });
        // When: completing one actual poll through the production admission.
        std::future::poll_fn(|cx| {
            assert!(fifth.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Then: blocked admission has not polled its application body.
        assert_eq!(observed.load(Ordering::SeqCst), 0);
        drop(permits.pop());
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(10), fifth)
                .await
                .unwrap(),
            b"hello"
        );
        assert!(observed.load(Ordering::SeqCst) > 0);
        println!("ADMISSION_BOUND permits=4 blocked_poll_completed=true fifth_body_polls=0");
    }

    #[tokio::test]
    async fn frame_backing_is_released_before_sdk_can_retain_it() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct Allocation(Vec<u8>, Arc<AtomicBool>);
        impl AsRef<[u8]> for Allocation {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl Drop for Allocation {
            fn drop(&mut self) {
                self.1.store(true, Ordering::SeqCst);
            }
        }
        for sliced in [false, true] {
            // Given: an adversarial Body frame owns a large backing allocation,
            // including a short slice which conceals that backing size.
            let dropped = Arc::new(AtomicBool::new(false));
            let bytes = axum::body::Bytes::from_owner(Allocation(
                vec![b'x'; 16 * 1024 * 1024],
                Arc::clone(&dropped),
            ));
            let frame = if sliced {
                let frame = bytes.slice(..65536);
                drop(bytes);
                frame
            } else {
                bytes
            };
            let size = u64::try_from(frame.len()).unwrap();
            let hash = format!("{:x}", Md5::digest(&frame));
            let mut reader = attachment_reader(
                Body::from(frame),
                &HeaderMap::new(),
                32 * 1024 * 1024,
                size,
                hash,
            )
            .unwrap();
            // When: requesting the first bounded reader window.
            let mut window = [0; 65536];
            let result = reader.read(&mut window).await;
            // Then: no external backing survives while SDK could retain reader.
            assert!(dropped.load(Ordering::SeqCst), "external backing retained");
            if sliced {
                assert_eq!(result.unwrap(), 65536);
            } else {
                assert!(result.is_err());
                assert_eq!(reader.error, Some(StatusCode::PAYLOAD_TOO_LARGE));
                assert_eq!(reader.bytes, 0);
            }
        }
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_size_hash_and_limit_plus_one() {
        for (size, hash, limit, expected, advanced) in [
            (5, "5d41402abc4b2a76b9719d911017c592", 5, None, 5),
            (
                4,
                "5d41402abc4b2a76b9719d911017c592",
                5,
                Some(StatusCode::BAD_REQUEST),
                5,
            ),
            (
                6,
                "5d41402abc4b2a76b9719d911017c592",
                6,
                Some(StatusCode::BAD_REQUEST),
                5,
            ),
            (
                5,
                "00000000000000000000000000000000",
                5,
                Some(StatusCode::BAD_REQUEST),
                5,
            ),
            (
                5,
                "5d41402abc4b2a76b9719d911017c592",
                4,
                Some(StatusCode::PAYLOAD_TOO_LARGE),
                0,
            ),
        ] {
            // Given: real bytes with independently supplied authorization.
            let mut reader = attachment_reader(
                Body::from("hello"),
                &HeaderMap::new(),
                limit,
                size,
                hash.into(),
            )
            .unwrap();
            // When: draining through the actual incremental verifier.
            let result = reader.read_to_end(&mut Vec::new()).await;
            // Then: only exact size/hash succeeds; overflow consumes max+1.
            assert_eq!(result.is_ok(), expected.is_none());
            assert_eq!(reader.error, expected);
            assert_eq!(reader.bytes, advanced);
        }
    }

    #[tokio::test]
    async fn gzip_validates_trailers_members_and_both_size_domains() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&vec![b'x'; 1024]).unwrap();
        let valid = encoder.finish().unwrap();
        let hash = format!("{:x}", Md5::digest(vec![b'x'; 1024]));
        let mut truncated = valid.clone();
        truncated.pop();
        let mut junk = valid.clone();
        junk.extend_from_slice(b"junk");
        for (body, limit, expected) in [
            (valid.clone(), 1024, None),
            (truncated, 1024, Some(StatusCode::BAD_REQUEST)),
            (junk, 1024, Some(StatusCode::BAD_REQUEST)),
            (valid.clone(), 1023, Some(StatusCode::PAYLOAD_TOO_LARGE)),
            (valid, 8, Some(StatusCode::PAYLOAD_TOO_LARGE)),
        ] {
            // Given: encoded HTTP gzip, independent decoded hash and size.
            let mut headers = HeaderMap::new();
            headers.insert("content-encoding", "gzip".parse().unwrap());
            let mut reader =
                attachment_reader(Body::from(body), &headers, limit, 1024, hash.clone()).unwrap();
            // When: consuming through the streaming decoder/verifier.
            let mut output = Vec::new();
            let result = reader.read_to_end(&mut output).await;
            // Then: corrupt/truncated/trailing data and either overflow fail.
            assert_eq!(result.is_ok(), expected.is_none());
            assert_eq!(reader.error, expected);
            if expected.is_none() {
                assert_eq!(output, vec![b'x'; 1024]);
            }
        }
        // Concatenated HTTP members form one attachment and one integrity check.
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"hello").unwrap();
        let member = encoder.finish().unwrap();
        let body = [member.as_slice(), member.as_slice()].concat();
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        let mut reader = attachment_reader(
            Body::from(body),
            &headers,
            1024,
            10,
            format!("{:x}", Md5::digest(b"hellohello")),
        )
        .unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"hellohello");
    }
}
