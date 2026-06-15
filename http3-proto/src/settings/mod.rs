//! HTTP/3 SETTINGS frame payload (RFC 9114 §7.2.4, RFC 9204 §5, RFC 9220 §3),
//! the tunnel-relevant subset. Encodes our settings; decodes and validates the
//! peer's (rejecting duplicates and reserved HTTP/2 identifiers, ignoring
//! unknown/GREASE settings). Dynamic-table capacity is always advertised as 0.

use crate::{
  error::TruncatedDetail,
  varint::{self, VarintError},
};

const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// HTTP/3 connection settings (the tunnel-relevant subset).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Settings {
  qpack_max_table_capacity: u64,
  qpack_blocked_streams: u64,
  max_field_section_size: Option<u64>,
  enable_connect_protocol: bool,
}

impl Settings {
  /// Our client settings: static-only QPACK; does not advertise Extended CONNECT.
  ///
  /// We intentionally do NOT advertise `SETTINGS_MAX_FIELD_SECTION_SIZE`
  /// (RFC 9114 §7.2.4.1): that setting bounds the *decoded* field-section size
  /// (each field's name+value length + 32 bytes overhead), but our decoder is
  /// lazy — it yields field lines one at a time and never buffers the whole
  /// decoded section — so there is no decoded-size DoS surface for the limit to
  /// protect. The on-wire *encoded* HEADERS payload is bounded internally at
  /// `HDR_CAP` (an oversize payload fails gracefully with `H3_FRAME_ERROR`),
  /// which is a separate, lower-level concern.
  pub const fn for_client() -> Self {
    Self {
      qpack_max_table_capacity: 0,
      qpack_blocked_streams: 0,
      max_field_section_size: None,
      enable_connect_protocol: false,
    }
  }

  /// Our server settings: static-only QPACK + Extended CONNECT enabled (RFC 9220).
  ///
  /// As with [`for_client`](Self::for_client), we intentionally do NOT advertise
  /// `SETTINGS_MAX_FIELD_SECTION_SIZE`: it limits the *decoded* field-section
  /// size, which our lazy decoder never accumulates, so it would over-promise. The
  /// *encoded* HEADERS payload is internally bounded at `HDR_CAP`.
  pub const fn for_server() -> Self {
    Self {
      qpack_max_table_capacity: 0,
      qpack_blocked_streams: 0,
      max_field_section_size: None,
      enable_connect_protocol: true,
    }
  }

  /// The advertised QPACK dynamic-table capacity (always 0 for us; 0 from a peer means no dynamic table).
  pub const fn qpack_max_table_capacity(&self) -> u64 {
    self.qpack_max_table_capacity
  }

  /// The advertised number of blocked streams.
  pub const fn qpack_blocked_streams(&self) -> u64 {
    self.qpack_blocked_streams
  }

  /// The peer's maximum field section size, if it sent one (`None` = unlimited).
  pub const fn max_field_section_size(&self) -> Option<u64> {
    self.max_field_section_size
  }

  /// Whether Extended CONNECT (RFC 9220 / RFC 8441) is enabled.
  pub const fn enable_connect_protocol(&self) -> bool {
    self.enable_connect_protocol
  }

  /// Encodes this settings set as a SETTINGS frame payload, returning bytes written.
  pub fn encode_payload(&self, out: &mut [u8]) -> Result<usize, SettingsError> {
    let mut at = put_setting(
      out,
      0,
      QPACK_MAX_TABLE_CAPACITY,
      self.qpack_max_table_capacity,
    )?;
    at = put_setting(out, at, QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams)?;
    if let Some(max) = self.max_field_section_size {
      at = put_setting(out, at, MAX_FIELD_SECTION_SIZE, max)?;
    }
    if self.enable_connect_protocol {
      at = put_setting(out, at, ENABLE_CONNECT_PROTOCOL, 1)?;
    }
    Ok(at)
  }

  /// Decodes and validates a peer's SETTINGS frame payload.
  pub fn decode_payload(input: &[u8]) -> Result<Self, SettingsError> {
    let mut s = Self::for_client(); // start from all-default (0 / None / false)
    let (mut seen_cap, mut seen_blocked, mut seen_max, mut seen_connect) =
      (false, false, false, false);
    let mut pos = 0usize;
    while pos < input.len() {
      let (n1, id) = varint::decode(input.get(pos..).unwrap_or(&[])).map_err(map_varint)?;
      pos = pos.saturating_add(n1);
      let (n2, value) = varint::decode(input.get(pos..).unwrap_or(&[])).map_err(map_varint)?;
      pos = pos.saturating_add(n2);
      match id {
        QPACK_MAX_TABLE_CAPACITY => {
          if seen_cap {
            return Err(SettingsError::Duplicate(id));
          }
          seen_cap = true;
          s.qpack_max_table_capacity = value;
        }
        QPACK_BLOCKED_STREAMS => {
          if seen_blocked {
            return Err(SettingsError::Duplicate(id));
          }
          seen_blocked = true;
          s.qpack_blocked_streams = value;
        }
        MAX_FIELD_SECTION_SIZE => {
          if seen_max {
            return Err(SettingsError::Duplicate(id));
          }
          seen_max = true;
          s.max_field_section_size = Some(value);
        }
        ENABLE_CONNECT_PROTOCOL => {
          if seen_connect {
            return Err(SettingsError::Duplicate(id));
          }
          if value > 1 {
            return Err(SettingsError::InvalidConnectProtocol(value));
          }
          seen_connect = true;
          s.enable_connect_protocol = value == 1;
        }
        0x02..=0x05 => return Err(SettingsError::Reserved(id)),
        _ => {} // unknown / GREASE — ignore
      }
    }
    Ok(s)
  }
}

/// Writes (id, value) as two varints at `at`, returning the new offset.
fn put_setting(out: &mut [u8], at: usize, id: u64, value: u64) -> Result<usize, SettingsError> {
  let a1 = put_varint(out, at, id)?;
  put_varint(out, a1, value)
}

fn put_varint(out: &mut [u8], at: usize, v: u64) -> Result<usize, SettingsError> {
  let slice = out.get_mut(at..).unwrap_or(&mut []);
  let n = varint::encode(v, slice).map_err(map_varint)?;
  Ok(at.saturating_add(n))
}

/// Maps a varint error: a truncated varint becomes Truncated (need more); others Varint.
fn map_varint(e: VarintError) -> SettingsError {
  match e {
    VarintError::Truncated(t) => SettingsError::Truncated(t),
    other => SettingsError::Varint(other),
  }
}

/// A SETTINGS payload error.
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Display)]
#[non_exhaustive]
pub enum SettingsError {
  /// The payload ended mid-setting (identifier or value incomplete).
  #[display("{_0}")]
  Truncated(TruncatedDetail),
  /// A known setting identifier occurred more than once (RFC 9114 §7.2.4.1).
  #[display("duplicate setting identifier {_0:#x}")]
  Duplicate(u64),
  /// An HTTP/2-reserved setting identifier was received (RFC 9114 §7.2.4.1).
  #[display("reserved http/2 setting identifier {_0:#x}")]
  Reserved(u64),
  /// SETTINGS_ENABLE_CONNECT_PROTOCOL carried a value other than 0 or 1
  /// (RFC 8441 §3 / RFC 9220).
  #[display("invalid ENABLE_CONNECT_PROTOCOL value {_0}")]
  InvalidConnectProtocol(u64),
  /// A setting identifier or value varint was malformed.
  #[display("{_0}")]
  Varint(VarintError),
}

#[cfg(test)]
mod tests;
