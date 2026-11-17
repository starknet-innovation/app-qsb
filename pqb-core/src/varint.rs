//! Bitcoin CompactSize integers, read incrementally from a byte stream.

use crate::error::{Error, Result};

/// Reads one CompactSize across any number of `feed` calls.
#[derive(Clone, Copy, Default)]
pub struct VarIntReader {
    /// Total bytes the encoding takes, known after the first byte.
    size: u8,
    got: u8,
    buf: [u8; 9],
}

impl VarIntReader {
    pub const fn new() -> Self {
        VarIntReader {
            size: 0,
            got: 0,
            buf: [0; 9],
        }
    }

    /// Consume bytes from `data`. Returns how many were used and, once the integer
    /// is complete, its value. Non-canonical encodings are refused, as Bitcoin Core does.
    pub fn feed(&mut self, data: &[u8]) -> Result<(usize, Option<u64>)> {
        let mut used = 0;
        while used < data.len() {
            let b = data[used];
            used += 1;
            if self.got == 0 {
                self.size = match b {
                    0..=0xfc => return Ok((used, Some(b as u64))),
                    0xfd => 3,
                    0xfe => 5,
                    0xff => 9,
                };
            }
            self.buf[self.got as usize] = b;
            self.got += 1;
            if self.got == self.size {
                let mut v = [0u8; 8];
                v[..self.size as usize - 1].copy_from_slice(&self.buf[1..self.size as usize]);
                let value = u64::from_le_bytes(v);
                let min = match self.size {
                    3 => 0xfd,
                    5 => 0x1_0000,
                    _ => 0x1_0000_0000,
                };
                if value < min {
                    return Err(Error::Parse);
                }
                return Ok((used, Some(value)));
            }
        }
        Ok((used, None))
    }
}

/// Encode `n` as a CompactSize. Returns the buffer and the number of bytes used.
pub fn encode(n: u64) -> ([u8; 9], usize) {
    let mut out = [0u8; 9];
    let len = if n < 0xfd {
        out[0] = n as u8;
        1
    } else if n <= 0xffff {
        out[0] = 0xfd;
        out[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        3
    } else if n <= 0xffff_ffff {
        out[0] = 0xfe;
        out[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        5
    } else {
        out[0] = 0xff;
        out[1..9].copy_from_slice(&n.to_le_bytes());
        9
    };
    (out, len)
}
