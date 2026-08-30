//! FIPS 180-4's SHA-256, so a digest this workspace publishes can be
//! recomputed with nothing but a checkout and a Rust toolchain.
//!
//! `xtask` takes no dependencies, and a digest that needed one — or that
//! shelled out to whichever of `shasum` and `sha256sum` the machine happens to
//! have — would be exactly the kind of number a reader cannot check.

/// The first thirty-two bits of the fractional parts of the cube roots of the
/// first sixty-four primes (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A running SHA-256, fed a chunk at a time so a hundred-megabyte dump never
/// has to be held whole.
pub struct Sha256 {
  state: [u32; 8],
  buffer: [u8; 64],
  buffered: usize,
  length: u64,
}

impl Default for Sha256 {
  fn default() -> Self {
    Self::new()
  }
}

impl Sha256 {
  /// The first thirty-two bits of the fractional parts of the square roots of
  /// the first eight primes (FIPS 180-4 §5.3.3).
  pub const fn new() -> Self {
    Self {
      state: [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
      ],
      buffer: [0; 64],
      buffered: 0,
      length: 0,
    }
  }

  /// Feeds the next bytes of the message.
  pub fn update(&mut self, mut bytes: &[u8]) {
    self.length = self.length.wrapping_add(bytes.len() as u64);
    while !bytes.is_empty() {
      let room = 64usize.saturating_sub(self.buffered);
      let take = room.min(bytes.len());
      let Some(slot) = self
        .buffer
        .get_mut(self.buffered..self.buffered.saturating_add(take))
      else {
        return;
      };
      let Some(head) = bytes.get(..take) else {
        return;
      };
      slot.copy_from_slice(head);
      self.buffered = self.buffered.saturating_add(take);
      bytes = bytes.get(take..).unwrap_or_default();
      if self.buffered == 64 {
        let block = self.buffer;
        self.compress(&block);
        self.buffered = 0;
      }
    }
  }

  /// The digest, lowercase hex.
  pub fn finish(mut self) -> String {
    let bits = self.length.wrapping_mul(8);
    self.update(&[0x80]);
    while self.buffered != 56 {
      self.update(&[0]);
    }
    // `update` counted the padding into `length`; the message length written
    // here is the one taken before it.
    let block = {
      let mut block = self.buffer;
      if let Some(tail) = block.get_mut(56..64) {
        tail.copy_from_slice(&bits.to_be_bytes());
      }
      block
    };
    self.compress(&block);

    let mut out = String::with_capacity(64);
    for word in self.state {
      out.push_str(&format!("{word:08x}"));
    }
    out
  }

  fn compress(&mut self, block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for index in 0..16 {
      let at = index * 4;
      let bytes = block.get(at..at + 4).unwrap_or(&[0; 4]);
      let word = u32::from_be_bytes([
        *bytes.first().unwrap_or(&0),
        *bytes.get(1).unwrap_or(&0),
        *bytes.get(2).unwrap_or(&0),
        *bytes.get(3).unwrap_or(&0),
      ]);
      if let Some(slot) = w.get_mut(index) {
        *slot = word;
      }
    }
    for index in 16..64 {
      let s0 = {
        let x = *w.get(index - 15).unwrap_or(&0);
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
      };
      let s1 = {
        let x = *w.get(index - 2).unwrap_or(&0);
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
      };
      let value = w
        .get(index - 16)
        .unwrap_or(&0)
        .wrapping_add(s0)
        .wrapping_add(*w.get(index - 7).unwrap_or(&0))
        .wrapping_add(s1);
      if let Some(slot) = w.get_mut(index) {
        *slot = value;
      }
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
    for index in 0..64 {
      let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
      let ch = (e & f) ^ ((!e) & g);
      let temp1 = h
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(*K.get(index).unwrap_or(&0))
        .wrapping_add(*w.get(index).unwrap_or(&0));
      let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = s0.wrapping_add(maj);
      h = g;
      g = f;
      f = e;
      e = d.wrapping_add(temp1);
      d = c;
      c = b;
      b = a;
      a = temp1.wrapping_add(temp2);
    }
    for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
      *slot = slot.wrapping_add(value);
    }
  }
}
