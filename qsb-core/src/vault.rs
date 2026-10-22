//! Recognising a QSB Config A vault script.
//!
//! qsb-app vaults (`protocol: qsb-config-a-v1`, generator commit `2c917205…`) are
//! bare output scripts of exactly 9,923 bytes. Everything in them is the same in
//! every vault except 300 HORS hash commitments: two rounds of 150 pushes of
//! 20 bytes, each push opcode `0x14` followed by the 20 committed bytes.
//!
//! ```text
//! offset  length
//!      0      62  pin signature push, OVER CHECKSIGVERIFY SHA256 SWAP CHECKSIGVERIFY
//!     62    3150  round 1: 150 × (0x14 || commitment[20])
//!   3212    1787  round 1 dummy signatures, CHECKMULTISIG dummy, nonce signature, program
//!   4999    3150  round 2: 150 × (0x14 || commitment[20])
//!   8149    1774  round 2 dummy signatures, CHECKMULTISIG dummy, nonce signature, program
//! ```
//!
//! A script matches when it has that length and the SHA-256 of its 3,923 fixed
//! bytes (everything outside the commitments, in order) equals `SKELETON_SHA256`.
//! The fixed bytes include the signatures QSB derives from constant seeds, the
//! OP_ROLL stack depths and both programs, so any other script is refused.
//!
//! A vault is identified by its script fingerprint: SHA-256 of the whole script,
//! not reversed. qsb-app calls it `scriptHash` and shows it as "Script
//! fingerprint"; it is also the Electrum-style script hash block explorers index.

use crate::hash::{Hashes, Sha256};

pub const VAULT_SCRIPT_LEN: u64 = 9923;

/// SHA-256 of the fixed bytes of every Config A vault script.
pub const SKELETON_SHA256: [u8; 32] = [
    0x68, 0xe4, 0x62, 0xa6, 0x37, 0xbb, 0xef, 0x84, 0x83, 0xda, 0x3b, 0x7f, 0x32, 0xa9, 0xa6, 0x8c,
    0x6d, 0x7b, 0x45, 0xcb, 0x82, 0x8f, 0xa1, 0xac, 0x4a, 0x6a, 0x2a, 0x87, 0x2e, 0x70, 0x1f, 0xeb,
];

/// Where each round's commitment pushes start.
const ROUNDS: [usize; 2] = [62, 4999];
const COMMITMENTS: usize = 150;
const PUSH: usize = 21;

/// From script offset `pos`: whether the byte is a commitment byte, and where
/// the run of bytes of the same kind ends.
fn run_at(pos: usize) -> (bool, usize) {
    for start in ROUNDS {
        if pos >= start && pos < start + COMMITMENTS * PUSH {
            let push = pos - (pos - start) % PUSH;
            return if pos == push {
                (false, push + 1)
            } else {
                (true, push + PUSH)
            };
        }
    }
    let next = ROUNDS
        .iter()
        .copied()
        .find(|&s| s > pos)
        .unwrap_or(VAULT_SCRIPT_LEN as usize);
    (false, next)
}

/// Checks a script streamed in pieces against the vault template.
pub struct VaultMatcher<H: Hashes> {
    candidate: bool,
    pos: usize,
    skeleton: H::Sha256,
    whole: H::Sha256,
}

impl<H: Hashes> VaultMatcher<H> {
    /// Start matching a script of `len` bytes.
    pub fn new(len: u64) -> Self {
        VaultMatcher {
            candidate: len == VAULT_SCRIPT_LEN,
            pos: 0,
            skeleton: H::Sha256::new(),
            whole: H::Sha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if !self.candidate {
            return;
        }
        if self.pos + data.len() > VAULT_SCRIPT_LEN as usize {
            self.candidate = false;
            return;
        }
        self.whole.update(data);
        let mut i = 0;
        while i < data.len() {
            let (commitment, end) = run_at(self.pos);
            let take = (end - self.pos).min(data.len() - i);
            if !commitment {
                self.skeleton.update(&data[i..i + take]);
            }
            i += take;
            self.pos += take;
        }
    }

    /// The script fingerprint if the script was a vault script.
    pub fn finish(self) -> Option<[u8; 32]> {
        if self.candidate
            && self.pos == VAULT_SCRIPT_LEN as usize
            && self.skeleton.finalize() == SKELETON_SHA256
        {
            Some(self.whole.finalize())
        } else {
            None
        }
    }
}
