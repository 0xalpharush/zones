use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{SinkExt as _, StreamExt as _};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Framed, LengthDelimitedCodec, LengthDelimitedCodecError};

use crate::{ErrorCode, PROTOCOL_VERSION, VerifyResponse};

/// A typed connection using the prover's length-delimited JSON protocol.
pub struct ProverConnection<T> {
    inner: Framed<WriteCounted<T>, LengthDelimitedCodec>,
    maximum: usize,
    last_received_bytes: Option<usize>,
    last_send_bytes: Option<usize>,
}

impl<IO> ProverConnection<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an I/O stream with the prover protocol and its maximum message size.
    pub fn new(io: IO, maximum: usize) -> Self {
        Self {
            inner: LengthDelimitedCodec::builder()
                .max_frame_length(maximum)
                .new_framed(WriteCounted {
                    inner: io,
                    written: 0,
                }),
            maximum,
            last_received_bytes: None,
            last_send_bytes: None,
        }
    }

    /// Returns the encoded size of the most recently received message.
    pub fn last_received_bytes(&self) -> Option<usize> {
        self.last_received_bytes
    }

    /// Intended JSON payload size for the latest send attempt, even if sending failed.
    /// None if serialization failed or no send was attempted.
    pub fn last_send_bytes(&self) -> Option<usize> {
        self.last_send_bytes
    }

    /// Bytes accepted by the underlying writer during the latest send attempt,
    /// including the four-byte frame prefix. This does not imply peer receipt and
    /// excludes transport overhead and retransmissions.
    pub fn last_send_written_bytes(&self) -> usize {
        self.inner.get_ref().written
    }

    /// Serializes and sends a typed message, returning its encoded size.
    /// Discard the connection after a failed or cancelled send; a partial frame
    /// may remain buffered.
    pub async fn send<T: Serialize>(
        &mut self,
        message: &T,
    ) -> Result<usize, ProverConnectionError> {
        self.last_send_bytes = None;
        self.inner.get_mut().written = 0;
        let payload = serde_json::to_vec(message).map_err(ProverConnectionError::Json)?;
        let bytes = payload.len();
        self.last_send_bytes = Some(bytes);
        self.inner
            .send(payload.into())
            .await
            .map_err(|error| classify_io_error(error, self.maximum))?;
        Ok(bytes)
    }

    /// Receives and deserializes a typed message.
    pub async fn receive<T: DeserializeOwned>(
        &mut self,
    ) -> Result<Option<T>, ProverConnectionError> {
        self.last_received_bytes = None;
        let Some(payload) = self.inner.next().await else {
            return Ok(None);
        };
        let payload = payload.map_err(|error| classify_io_error(error, self.maximum))?;
        self.last_received_bytes = Some(payload.len());
        serde_json::from_slice(&payload)
            .map(Some)
            .map_err(ProverConnectionError::Json)
    }
}

struct WriteCounted<T> {
    inner: T,
    written: usize,
}

impl<T: AsyncRead + Unpin> AsyncRead for WriteCounted<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WriteCounted<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(bytes)) = &result {
            self.written += bytes;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverConnectionError {
    #[error("message exceeds the maximum of {maximum} bytes")]
    MessageTooLarge { maximum: usize },
    #[error("message frame is truncated")]
    TruncatedFrame,
    #[error("message JSON is invalid: {0}")]
    Json(#[source] serde_json::Error),
    #[error("connection I/O failed: {0}")]
    Io(#[source] io::Error),
}

fn classify_io_error(error: io::Error, maximum: usize) -> ProverConnectionError {
    if error
        .get_ref()
        .is_some_and(|source| source.is::<LengthDelimitedCodecError>())
    {
        ProverConnectionError::MessageTooLarge { maximum }
    } else if error.kind() == io::ErrorKind::Other
        && error.to_string() == "bytes remaining on stream"
    {
        ProverConnectionError::TruncatedFrame
    } else {
        ProverConnectionError::Io(error)
    }
}

/// Converts a request receive error into a prover protocol response.
pub fn request_error_response(error: &ProverConnectionError) -> VerifyResponse {
    let (code, message) = match error {
        ProverConnectionError::MessageTooLarge { maximum } => (
            ErrorCode::RequestTooLarge,
            format!("request payload exceeds the maximum of {maximum} bytes"),
        ),
        ProverConnectionError::TruncatedFrame => (
            ErrorCode::TruncatedFrame,
            "request frame is truncated".into(),
        ),
        ProverConnectionError::Json(error) => (
            ErrorCode::MalformedRequest,
            format!("invalid request JSON: {error}"),
        ),
        ProverConnectionError::Io(error) => (
            ErrorCode::InternalError,
            format!("frame I/O failed: {error}"),
        ),
    };
    VerifyResponse::Error {
        version: PROTOCOL_VERSION,
        request_id: None,
        code,
        message,
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use alloy_primitives::{Address, B256, Bytes};
    use reth_trie_common::EMPTY_ROOT_HASH;
    use tempo_primitives::TempoHeader;
    use tokio::io::AsyncWriteExt as _;
    use zone_spf::{BatchWitness, PublicInputs, TempoStateWitness, ZoneStateWitness};

    use super::*;
    use crate::VerifyRequest;

    /// A writer that accepts short writes before failing at a deterministic offset.
    #[derive(Default)]
    struct FailingWriter {
        bytes: Vec<u8>,
        limit: usize,
        fail_flush: bool,
    }

    impl AsyncRead for FailingWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = buf.len().min(2).min(self.limit - self.bytes.len());
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            self.bytes.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(if self.fail_flush {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            })
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn send_sizes_survive_partial_write_and_flush_failures() {
        let message = "payload";
        let payload = serde_json::to_vec(message).unwrap();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);

        // No bytes, partial prefix, partial payload, and complete frame + failed flush.
        for limit in [0, 2, 7, frame.len()] {
            let mut connection = ProverConnection::new(
                FailingWriter {
                    limit,
                    fail_flush: true,
                    ..Default::default()
                },
                1024,
            );
            let error = connection.send(&message).await.unwrap_err();
            assert!(matches!(error, ProverConnectionError::Io(_)));
            assert_eq!(connection.last_send_bytes(), Some(payload.len()));
            assert_eq!(connection.last_send_written_bytes(), limit);
            assert_eq!(connection.inner.get_ref().inner.bytes, frame[..limit]);
        }
    }

    #[tokio::test]
    async fn send_sizes_reset_between_attempts() {
        let (writer, _reader) = tokio::io::duplex(1024);
        let mut connection = ProverConnection::new(writer, 16);
        assert_eq!(connection.last_send_bytes(), None);
        assert_eq!(connection.last_send_written_bytes(), 0);
        for message in ["first", "second"] {
            let bytes = connection.send(&message).await.unwrap();
            assert_eq!(connection.last_send_bytes(), Some(bytes));
            assert_eq!(connection.last_send_written_bytes(), bytes + 4);
        }

        let oversized = "x".repeat(32);
        assert!(matches!(
            connection.send(&oversized).await,
            Err(ProverConnectionError::MessageTooLarge { .. })
        ));
        assert_eq!(connection.last_send_bytes(), Some(34));
        assert_eq!(connection.last_send_written_bytes(), 0);
    }

    #[tokio::test]
    async fn serialization_failure_has_no_intended_or_written_bytes() {
        struct InvalidMessage;
        impl Serialize for InvalidMessage {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(
                    "intentional serialization failure",
                ))
            }
        }
        let (writer, _reader) = tokio::io::duplex(1024);
        let mut connection = ProverConnection::new(writer, 1024);
        connection.send(&"previous").await.unwrap();
        assert!(matches!(
            connection.send(&InvalidMessage).await,
            Err(ProverConnectionError::Json(_))
        ));
        assert_eq!(connection.last_send_bytes(), None);
        assert_eq!(connection.last_send_written_bytes(), 0);
    }

    #[tokio::test]
    async fn request_round_trip() {
        let maximum = 1024 * 1024;
        let (client, server) = tokio::io::duplex(maximum);
        let mut client = ProverConnection::new(client, maximum);
        let mut server = ProverConnection::new(server, maximum);
        let request = VerifyRequest {
            version: PROTOCOL_VERSION,
            request_id: "round-trip".into(),
            witness: empty_witness(),
        };
        let sent_bytes = client.send(&request).await.unwrap();
        let received: VerifyRequest = server.receive().await.unwrap().unwrap();

        assert_eq!(received.version, PROTOCOL_VERSION);
        assert_eq!(received.request_id, "round-trip");
        assert_eq!(server.last_received_bytes(), Some(sent_bytes));

        let response = VerifyResponse::Error {
            version: PROTOCOL_VERSION,
            request_id: Some(received.request_id),
            code: ErrorCode::VerificationFailed,
            message: "round-trip".into(),
        };
        let sent_bytes = server.send(&response).await.unwrap();
        let received: VerifyResponse = client.receive().await.unwrap().unwrap();
        assert!(matches!(
            received,
            VerifyResponse::Error {
                request_id: Some(id),
                code: ErrorCode::VerificationFailed,
                ..
            } if id == "round-trip"
        ));
        assert_eq!(client.last_received_bytes(), Some(sent_bytes));
    }

    #[tokio::test]
    async fn rejects_oversized_and_truncated_frames() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(&10_u32.to_be_bytes()).await.unwrap();
        let error = ProverConnection::new(reader, 4)
            .receive::<VerifyRequest>()
            .await
            .unwrap_err();
        assert!(matches!(
            request_error_response(&error),
            VerifyResponse::Error {
                code: ErrorCode::RequestTooLarge,
                ..
            }
        ));

        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(&[0, 0, 0, 2, 1]).await.unwrap();
        writer.shutdown().await.unwrap();
        let error = ProverConnection::new(reader, 4)
            .receive::<VerifyRequest>()
            .await
            .unwrap_err();
        assert!(matches!(
            request_error_response(&error),
            VerifyResponse::Error {
                code: ErrorCode::TruncatedFrame,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn malformed_json_has_a_stable_error() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(&8_u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"not json").await.unwrap();
        let error = ProverConnection::new(reader, 1024)
            .receive::<VerifyRequest>()
            .await
            .unwrap_err();
        let response = request_error_response(&error);
        assert!(matches!(
            response,
            VerifyResponse::Error {
                request_id: None,
                code: ErrorCode::MalformedRequest,
                ..
            }
        ));
    }

    fn empty_witness() -> BatchWitness {
        let tempo_header = TempoHeader {
            inner: Header {
                number: 2,
                state_root: EMPTY_ROOT_HASH,
                ..Default::default()
            },
            ..Default::default()
        };
        BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: 42_431,
                zone_id: 1,
                portal: Address::repeat_byte(0x11),
                tempo_block_number: 2,
                anchor_block_number: 2,
                anchor_block_hash: B256::ZERO,
                expected_withdrawal_batch_index: 3,
            },
            parent_header: TempoHeader::default(),
            zone_blocks: Vec::new(),
            zone_state_witness: ZoneStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            tempo_state_witness: TempoStateWitness {
                initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(tempo_header)),
                node_pool: Vec::new(),
            },
            tempo_ancestry_headers: Vec::new(),
        }
    }
}
