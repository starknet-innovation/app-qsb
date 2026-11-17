//! The `PQB-v1` locking script template.
//!
//! A PQB vault's scriptPubKey is a bare legacy script of 4,696 bytes, built by
//! the pqb implementation (construction version `v1`, configuration `PQB`, real
//! puzzles; pqb commit `bb2ddca`). Its only seed-dependent content is the 154
//! commitments of the root `R`, each a 20-byte push (`0x14 || commitment`) at a
//! fixed offset. `template.bin` is that script with every commitment zeroed;
//! `tools/pqb_template.py` regenerates it from pqb, rediscovers the layout below
//! for several seeds, and fails if it no longer matches this file.
//!
//! In script order the slots are:
//!
//! ```text
//! push at   stride  count  root indices      what
//!       6        -      1  153               q, the co-signing key's HASH160
//!      34       21     12  109..121          m_pin
//!     306       31    109  0..109            c[0..109] (each push follows a dummy signature)
//!    3675       21     16  121..137          m_round0
//!    4175       21     16  137..153          m_round1
//! ```
//!
//! The script contains no OP_CODESEPARATOR, so the co-signature's scriptCode is
//! the whole script.

pub const SCRIPT_LEN: usize = 4696;

pub static TEMPLATE: &[u8; SCRIPT_LEN] = include_bytes!("template.bin");

/// (offset of the first push opcode, stride, count, first root index), in script order.
const LAYOUT: [(usize, usize, usize, usize); 5] = [
    (6, 0, 1, 153),
    (34, 21, 12, 109),
    (306, 31, 109, 0),
    (3675, 21, 16, 121),
    (4175, 21, 16, 137),
];

pub const SLOTS: usize = 154;

/// Slot `k` in script order: (offset of its 20 committed bytes, root index).
pub fn slot(k: usize) -> (usize, usize) {
    let mut k = k;
    for (push, stride, count, first) in LAYOUT {
        if k < count {
            return (push + k * stride + 1, first + k);
        }
        k -= count;
    }
    (SCRIPT_LEN, 0)
}
