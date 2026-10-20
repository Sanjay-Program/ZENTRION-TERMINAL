//! Session wire protocol: JSON-RPC 2.0 plus binary output frames.
//!
//! Every frame is `u32 BE length | u8 type | payload`. Type 0 is a JSON-RPC
//! message, type 1 is a binary terminal-output frame, type 2 a scrollback
//! chunk (reserved; replay uses type 1 with the same sequence numbering).
//!
//! The length prefix bounds every allocation ([`MAX_FRAME`]), so a hostile or
//! buggy peer cannot make the daemon reserve unbounded memory.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const TYPE_JSON: u8 = 0;
pub const TYPE_OUTPUT: u8 = 1;
pub const TYPE_SCROLLBACK: u8 = 2;

/// Maximum accepted frame (16 MiB). Terminal chunks are 16 KiB; JSON-RPC
/// requests are far smaller.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;
pub const ERR_NOT_FOUND: i64 = -32001;
pub const ERR_DENIED: i64 = -32002;
pub const ERR_UNAVAILABLE: i64 = -32003;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<u64>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: Option<u64>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<u64>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// A live output frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputFrame {
    pub seq: u64,
    pub session_id: String,
    #[serde(skip)]
    pub data: Vec<u8>,
}

impl OutputFrame {
    pub fn encode(&self) -> Vec<u8> {
        let id = self.session_id.as_bytes();
        let id_len = id.len().min(u16::MAX as usize);
        let mut payload = Vec::with_capacity(8 + 2 + id_len + self.data.len());
        payload.extend_from_slice(&self.seq.to_be_bytes());
        payload.extend_from_slice(&(id_len as u16).to_be_bytes());
        payload.extend_from_slice(&id[..id_len]);
        payload.extend_from_slice(&self.data);
        frame(TYPE_OUTPUT, &payload)
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < 10 {
            return None;
        }
        let seq = u64::from_be_bytes(payload[0..8].try_into().ok()?);
        let id_len = u16::from_be_bytes(payload[8..10].try_into().ok()?) as usize;
        if payload.len() < 10 + id_len {
            return None;
        }
        let session_id = String::from_utf8(payload[10..10 + id_len].to_vec()).ok()?;
        Some(Self {
            seq,
            session_id,
            data: payload[10 + id_len..].to_vec(),
        })
    }
}

pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

pub fn json_frame<T: Serialize>(message: &T) -> Vec<u8> {
    match serde_json::to_vec(message) {
        Ok(payload) => frame(TYPE_JSON, &payload),
        Err(error) => frame(
            TYPE_JSON,
            serde_json::to_vec(&RpcResponse::err(
                None,
                ERR_INTERNAL,
                format!("cannot serialize response: {error}"),
            ))
            .unwrap_or_default()
            .as_slice(),
        ),
    }
}

pub fn notification(method: &str, params: Value) -> Vec<u8> {
    json_frame(&json!({"jsonrpc":"2.0","method":method,"params":params}))
}

/// Parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: u8,
    pub len: usize,
}

pub fn parse_header(bytes: &[u8; 5]) -> Result<FrameHeader, String> {
    let len = u32::from_be_bytes(bytes[0..4].try_into().expect("4 bytes")) as usize;
    if len > MAX_FRAME {
        return Err(format!("frame of {len} bytes exceeds maximum {MAX_FRAME}"));
    }
    Ok(FrameHeader {
        kind: bytes[4],
        len,
    })
}

/// Parse a complete frame from a buffer. Returns the message and bytes used.
pub fn parse_frame(buffer: &[u8]) -> Result<Option<(u8, Vec<u8>, usize)>, String> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    let header = parse_header(&buffer[0..5].try_into().expect("5 bytes"))?;
    if buffer.len() < 5 + header.len {
        return Ok(None);
    }
    Ok(Some((
        header.kind,
        buffer[5..5 + header.len].to_vec(),
        5 + header.len,
    )))
}

pub fn parse_json<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, String> {
    serde_json::from_slice(payload).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_frame_round_trips() {
        let frame = OutputFrame {
            seq: 42,
            session_id: "s_abc".into(),
            data: b"hello \x1b[31mworld".to_vec(),
        };
        let encoded = frame.encode();
        let (kind, payload, used) = parse_frame(&encoded).unwrap().unwrap();
        assert_eq!(kind, TYPE_OUTPUT);
        assert_eq!(used, encoded.len());
        let decoded = OutputFrame::decode(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn oversized_frames_are_rejected() {
        let mut bytes = [0u8; 5];
        bytes[0..4].copy_from_slice(&(u32::MAX).to_be_bytes());
        assert!(parse_header(&bytes).is_err());
    }

    #[test]
    fn incomplete_frames_return_none() {
        assert!(parse_frame(&[0, 0]).unwrap().is_none());
        assert!(parse_frame(&[0, 0, 0, 4, 0, 1, 2]).unwrap().is_none());
    }

    #[test]
    fn rpc_error_has_code_and_no_result() {
        let response = RpcResponse::err(Some(7), ERR_INVALID_PARAMS, "bad");
        let text = serde_json::to_string(&response).unwrap();
        assert!(text.contains("\"code\":-32602"));
        assert!(!text.contains("result"));
    }

    #[test]
    fn request_accepts_notification_without_id() {
        let request: RpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"session.input"}"#).unwrap();
        assert!(request.id.is_none());
    }
}
