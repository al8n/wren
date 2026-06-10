//! Lossless RFC 6455 §5.2 frame codec.
//!
//! This layer parses and serializes frames without enforcing protocol
//! policy: reserved opcodes and RSV bits are surfaced losslessly (the
//! connection state machine rejects them per its negotiated configuration),
//! and masking is a pure transform with no direction rules. Length
//! canonicality, however, IS wire grammar (§5.2 requires minimal length
//! encoding and a zero MSB on 64-bit lengths) and is enforced here.

mod close;
mod header;
mod mask;
mod opcode;

pub use close::{
  CloseCode, ClosePayloadError, DecodedClose, decode_close_payload, encode_close_payload,
};
pub use header::{
  DecodeError, Decoded, DecodedHeader, FrameHeader, MoreNeeded, NonCanonicalLengthDetail,
};
pub use mask::mask;
pub use opcode::Opcode;
