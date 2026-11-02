use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The maximum frame size in bytes to prevent too large of requests/responses.
pub const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

/// An incoming request from the CLI to the daemon.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "action", content = "payload")]
pub enum IpcRequest {
    Wrap { aad: Vec<u8>, plaintext: String },
    Unwrap { aad: Vec<u8>, ciphertext: String },
    Status,
    Lock,
    Stop,
}

/// A response coming from the daemon for the CLI.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Success {
        value: String,
    },
    Status {
        is_locked: bool,
        remaining_ttl_seconds: Option<u64>,
    },
    Locked,
    Stopped,
    Error {
        message: String,
    },
}

/// Writes a JSON frame to an async writer.
///
/// Framing structure:
/// - 4 bytes: payload length in bytes (u32 big-endian)
/// - Payload bytes: UTF-8 encoded JSON
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    // convert the message to bytes.
    let bytes = serde_json::to_vec(message)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;

    // if the message is too big, give an error.
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "frame size {} exceeds maximum {}",
                bytes.len(),
                MAX_FRAME_SIZE
            ),
        ));
    }

    // write the message to the writer
    let len = bytes.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;

    Ok(())
}

/// Reads a JSON frame from an async reader.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, Error>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    // figure out the length of the json from the first 4 bytes.
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // if the message is too large, raise an error.
    if len > MAX_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE),
        ));
    }

    // build the buffer from the message using the length.
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    // JSON decode the response.
    serde_json::from_slice(&buf).map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn roundtrip_wrap_request() {
        let req = IpcRequest::Wrap {
            aad: b"test-aad".to_vec(),
            plaintext: "super-secret".to_string(),
        };

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &req).await.unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded: IpcRequest = read_frame(&mut cursor).await.unwrap();

        assert_eq!(req, decoded);
    }

    #[tokio::test]
    async fn roundtrip_unwrap_request() {
        let req = IpcRequest::Unwrap {
            aad: b"test-aad".to_vec(),
            ciphertext: "c9s-yk1:enc-secret".to_string(),
        };

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &req).await.unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded: IpcRequest = read_frame(&mut cursor).await.unwrap();

        assert_eq!(req, decoded);
    }

    #[tokio::test]
    async fn roundtrip_status_and_lock_and_stop_requests() {
        for req in [IpcRequest::Status, IpcRequest::Lock, IpcRequest::Stop] {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &req).await.unwrap();

            let mut cursor = Cursor::new(buffer);
            let decoded: IpcRequest = read_frame(&mut cursor).await.unwrap();

            assert_eq!(req, decoded);
        }
    }

    #[tokio::test]
    async fn roundtrip_responses() {
        let responses = vec![
            IpcResponse::Success {
                value: "decrypted".to_string(),
            },
            IpcResponse::Status {
                is_locked: false,
                remaining_ttl_seconds: Some(600),
            },
            IpcResponse::Status {
                is_locked: true,
                remaining_ttl_seconds: None,
            },
            IpcResponse::Locked,
            IpcResponse::Stopped,
            IpcResponse::Error {
                message: "Access denied".to_string(),
            },
        ];

        for resp in responses {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &resp).await.unwrap();

            let mut cursor = Cursor::new(buffer);
            let decoded: IpcResponse = read_frame(&mut cursor).await.unwrap();

            assert_eq!(resp, decoded);
        }
    }

    #[tokio::test]
    async fn frame_exceeding_max_size_fails() {
        let len = (MAX_FRAME_SIZE + 1) as u32;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len.to_be_bytes());
        buffer.extend_from_slice(&[0u8; 10]);

        let mut cursor = Cursor::new(buffer);
        let result: Result<IpcRequest, _> = read_frame(&mut cursor).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }
}
