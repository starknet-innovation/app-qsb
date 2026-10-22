//! The one-time reveal guard.
//!
//! HORS is a few-time scheme: every extra reveal for the same commitments hands
//! out preimages an attacker can combine into new valid subsets. The device keeps
//! one record per vault it has revealed for and refuses a second, different set.
//! Re-revealing the same set (same indices, same withdrawal) is allowed, so a
//! failed broadcast can be retried.
//!
//! A vault is identified by its wallet as well as its network and index: the app's
//! storage is shared by every seed the device unlocks (a BIP-39 passphrase gives
//! another seed, so other secrets), and vault #0 of one must not block vault #0
//! of another. The wallet tag is `HMAC-SHA256(K, "QSB-HORS-v1/guard")[0..8)`
//! (`hors::wallet_tag`), which says nothing about `K`.
//!
//! The table is a fixed-size blob the device keeps in NVM and replaces
//! atomically. Layout:
//!
//! ```text
//! offset 0  layout version (0x01; 0x00 = never written, an empty table)
//! offset 1  entry count, ≤ 64
//! offset 2  64 entries of 46 bytes, oldest first:
//!           wallet tag (8) ‖ net (1) ‖ v (4, big-endian) ‖ state (1, 0x01 = revealed) ‖ reveal hash (32)
//! ```
//!
//! Anything else is unreadable, and the guard then refuses every reveal rather
//! than forget what it recorded. It covers this device and this install only:
//! another device with the same seed, a reset or a reinstall has no record.

use crate::error::{Error, Result};
use crate::hors::Vault;

pub const CAPACITY: usize = 64;
pub const ENTRY_LEN: usize = 46;
pub const TABLE_LEN: usize = 2 + CAPACITY * ENTRY_LEN;

const NEVER_WRITTEN: u8 = 0x00;
const LAYOUT_V1: u8 = 0x01;
const REVEALED: u8 = 0x01;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub wallet: [u8; 8],
    pub vault: Vault,
    pub reveal_hash: [u8; 32],
}

/// What a reveal request meets in the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Check {
    /// No record for this vault. `evict` is the oldest entry, which recording
    /// this reveal will drop, when the table is full.
    New { evict: Option<Entry> },
    /// The same reveal is already recorded.
    ReReveal,
    /// A different reveal is recorded for this vault.
    Conflict,
}

/// The recorded entries, oldest first, or `GuardCorrupt` if the table isn't one
/// this code wrote.
fn read(table: &[u8; TABLE_LEN]) -> Result<impl Iterator<Item = Entry> + '_> {
    let count = match table[0] {
        NEVER_WRITTEN if table.iter().all(|&b| b == 0) => 0,
        LAYOUT_V1 if (table[1] as usize) <= CAPACITY => table[1] as usize,
        _ => return Err(Error::GuardCorrupt),
    };
    let entries = &table[2..2 + count * ENTRY_LEN];
    if entries.chunks(ENTRY_LEN).any(|e| e[13] != REVEALED) {
        return Err(Error::GuardCorrupt);
    }
    Ok(entries.chunks(ENTRY_LEN).map(|e| Entry {
        wallet: e[0..8].try_into().unwrap_or([0; 8]),
        vault: Vault {
            net: e[8],
            index: u32::from_be_bytes([e[9], e[10], e[11], e[12]]),
        },
        reveal_hash: e[14..46].try_into().unwrap_or([0; 32]),
    }))
}

pub fn entries(table: &[u8; TABLE_LEN]) -> Result<impl Iterator<Item = Entry> + '_> {
    read(table)
}

/// Whether `wallet`'s vault has a recorded reveal.
pub fn revealed(table: &[u8; TABLE_LEN], wallet: &[u8; 8], vault: Vault) -> Result<bool> {
    Ok(read(table)?.any(|e| e.wallet == *wallet && e.vault == vault))
}

pub fn check(
    table: &[u8; TABLE_LEN],
    wallet: &[u8; 8],
    vault: Vault,
    reveal_hash: &[u8; 32],
) -> Result<Check> {
    let found = read(table)?.find(|e| e.wallet == *wallet && e.vault == vault);
    Ok(match found {
        Some(e) if e.reveal_hash == *reveal_hash => Check::ReReveal,
        Some(_) => Check::Conflict,
        None => Check::New {
            evict: if read(table)?.count() == CAPACITY {
                read(table)?.next()
            } else {
                None
            },
        },
    })
}

/// Write into `out` the table with `new` recorded, dropping the oldest entry if
/// it is full. The caller stores `out` in one atomic update before any preimage
/// leaves. (`out` is the caller's so the device can keep 3 kB off its stack.)
pub fn record_into(table: &[u8; TABLE_LEN], new: Entry, out: &mut [u8; TABLE_LEN]) -> Result<()> {
    let count = read(table)?.count();
    let skip = count + 1 - (count + 1).min(CAPACITY);
    out.fill(0);
    out[0] = LAYOUT_V1;
    let mut n = 0;
    for e in read(table)?.skip(skip).chain(core::iter::once(new)) {
        let at = 2 + n * ENTRY_LEN;
        out[at..at + 8].copy_from_slice(&e.wallet);
        out[at + 8] = e.vault.net;
        out[at + 9..at + 13].copy_from_slice(&e.vault.index.to_be_bytes());
        out[at + 13] = REVEALED;
        out[at + 14..at + ENTRY_LEN].copy_from_slice(&e.reveal_hash);
        n += 1;
    }
    out[1] = n as u8;
    Ok(())
}
