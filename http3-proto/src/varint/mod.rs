//! QUIC variable-length integers (RFC 9000 §16).

use crate::error::{BufferTooSmallDetail, TruncatedDetail};

/// Largest value a QUIC varint can hold (2^62 − 1).
pub const MAX: u64 = (1 << 62) - 1;

/// A varint codec error.
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum VarintError {
  /// The output buffer was too small.
  #[error(transparent)]
  Buffer(#[from] BufferTooSmallDetail),
  /// The input ended mid-integer.
  #[error(transparent)]
  Truncated(#[from] TruncatedDetail),
  /// The value exceeds [`MAX`] and cannot be encoded.
  #[error("varint value exceeds 2^62-1")]
  TooLarge,
}

/// Bytes a value encodes to: 1, 2, 4, or 8.
#[inline]
pub const fn len_of(value: u64) -> usize {
  if value <= 0x3f {
    1
  } else if value <= 0x3fff {
    2
  } else if value <= 0x3fff_ffff {
    4
  } else {
    8
  }
}

/// Encodes `value` into `out`, returning bytes written.
#[inline]
pub fn encode(value: u64, out: &mut [u8]) -> Result<usize, VarintError> {
  if value > MAX {
    return Err(VarintError::TooLarge);
  }
  match len_of(value) {
    1 => {
      let byte = u8::try_from(value).map_err(|_| VarintError::TooLarge)?;
      out_prefix::<1>(out)?.copy_from_slice(&[byte]);
      Ok(1)
    }
    2 => {
      let encoded = u16::try_from(value).map_err(|_| VarintError::TooLarge)? | 0x4000;
      out_prefix::<2>(out)?.copy_from_slice(&encoded.to_be_bytes());
      Ok(2)
    }
    4 => {
      let encoded = u32::try_from(value).map_err(|_| VarintError::TooLarge)? | 0x8000_0000;
      out_prefix::<4>(out)?.copy_from_slice(&encoded.to_be_bytes());
      Ok(4)
    }
    _ => {
      let encoded = value | 0xc000_0000_0000_0000;
      out_prefix::<8>(out)?.copy_from_slice(&encoded.to_be_bytes());
      Ok(8)
    }
  }
}

/// Decodes a varint from the front of `input`: (bytes consumed, value).
#[inline]
pub fn decode(input: &[u8]) -> Result<(usize, u64), VarintError> {
  let &first = input.first().ok_or(TruncatedDetail::new(1))?;
  match first >> 6 {
    0 => Ok((1, u64::from(first & 0x3f))),
    1 => {
      let [b0, b1] = input_array::<2>(input)?;
      Ok((2, u64::from(u16::from_be_bytes([b0 & 0x3f, b1]))))
    }
    2 => {
      let [b0, b1, b2, b3] = input_array::<4>(input)?;
      Ok((4, u64::from(u32::from_be_bytes([b0 & 0x3f, b1, b2, b3]))))
    }
    _ => {
      let [b0, b1, b2, b3, b4, b5, b6, b7] = input_array::<8>(input)?;
      Ok((
        8,
        u64::from_be_bytes([b0 & 0x3f, b1, b2, b3, b4, b5, b6, b7]),
      ))
    }
  }
}

#[inline]
fn out_prefix<const N: usize>(out: &mut [u8]) -> Result<&mut [u8], VarintError> {
  let out_len = out.len();
  out
    .get_mut(..N)
    .ok_or_else(|| VarintError::Buffer(BufferTooSmallDetail::new(N, out_len)))
}

#[inline]
fn input_array<const N: usize>(input: &[u8]) -> Result<[u8; N], VarintError> {
  let needed = N.saturating_sub(input.len());
  let bytes = input.get(..N).ok_or(TruncatedDetail::new(needed))?;
  <[u8; N]>::try_from(bytes).map_err(|_| VarintError::Truncated(TruncatedDetail::new(needed)))
}

#[cfg(test)]
mod tests;
