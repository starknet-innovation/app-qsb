//! The device's persistent PQB state: per seed an allocation high-water mark,
//! per vault a disclosure record (BIP "Allocation", "Disclosure lifecycle").
//!
//! The store is a set of fixed 256-byte slots the device keeps in NVM, each
//! replaced atomically (two copies, switched once the new one is written).
//! Slot 0 holds the namespaces, slots 1..=CAPACITY one vault record each.
//!
//! ```text
//! namespace slot: 0x01 (layout) || count (1) || count × [wallet id (16) || state (1) || next_v (4, BE)]
//!                 namespace state: 0x01 fresh, 0x02 unknown (continuity lost)
//!
//! record slot:    0x01 (layout) || wallet id (16) || v (4, BE) || state (1) || flags (1)
//!                 || R (32) || script hash (32)
//!                 || funding txid (32, internal order) || vout (4, LE) || value (8, LE)
//!                 || sweep input outpoint (36)
//!                 || round0 (8) || round1 (9) || picks (3) || B (32) || D (32) || zero (5)
//!                 state: 0x01 allocated, 0x02 exposed, 0x03 retired, 0x04 unknown
//!                 flags: 0x01 funded, 0x02 disclosure recorded, 0x04 emergency
//! ```
//!
//! An all-zero slot is empty. Anything else that isn't exactly one of these is
//! unreadable, and the device then refuses every allocation and disclosure:
//! torn or corrupt state fails closed.
//!
//! Allocation writes the record before raising `next_v`, so a crash between the
//! two leaves the index taken; the effective `next_v` is the larger of the
//! stored one and every recorded index + 1. Indices below `next_v` without a
//! record are permanently reserved (retired records of a fresh namespace are
//! dropped that way, to make room).

use crate::error::{Error, Result};

pub const SLOT_LEN: usize = 256;
pub const CAPACITY: usize = 32;
pub const SLOTS: usize = CAPACITY + 1;
pub const MAX_NAMESPACES: usize = 8;

const LAYOUT_V1: u8 = 0x01;
const NS_ENTRY: usize = 21;

pub type Slot = [u8; SLOT_LEN];

/// Persistent slots. The device's are in NVM; tests use memory.
pub trait Store {
    fn read(&self, slot: usize) -> &Slot;
    /// Replace a slot durably before returning.
    fn write(&mut self, slot: usize, data: &Slot);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NsState {
    /// The user declared this seed never used for PQB before this device's history.
    Fresh,
    /// No trustworthy history: no allocation, and disclosure only on the emergency path.
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Namespace {
    pub wallet: [u8; 16],
    pub state: NsState,
    pub next_v: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Allocated,
    Exposed,
    Retired,
    Unknown,
}

impl State {
    pub fn byte(self) -> u8 {
        match self {
            State::Allocated => 1,
            State::Exposed => 2,
            State::Retired => 3,
            State::Unknown => 4,
        }
    }

    fn from_byte(b: u8) -> Option<State> {
        Some(match b {
            1 => State::Allocated,
            2 => State::Exposed,
            3 => State::Retired,
            4 => State::Unknown,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Funding {
    /// Internal (serialization) byte order.
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    /// One input of the sweep that funded it: another sweep is accepted only if
    /// it spends this too, so at most one of them can confirm.
    pub sweep_input: [u8; 36],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Disclosure {
    pub round0: [u8; 8],
    pub round1: [u8; 9],
    pub picks: [u8; 3],
    pub binding: [u8; 32],
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Record {
    pub wallet: [u8; 16],
    pub v: u32,
    pub state: State,
    pub emergency: bool,
    pub root: [u8; 32],
    pub script_hash: [u8; 32],
    pub funding: Option<Funding>,
    pub disclosure: Option<Disclosure>,
}

const F_FUNDED: u8 = 0x01;
const F_DISCLOSED: u8 = 0x02;
const F_EMERGENCY: u8 = 0x04;

impl Record {
    pub fn encode(&self) -> Slot {
        let mut s = [0u8; SLOT_LEN];
        s[0] = LAYOUT_V1;
        s[1..17].copy_from_slice(&self.wallet);
        s[17..21].copy_from_slice(&self.v.to_be_bytes());
        s[21] = self.state.byte();
        s[22] = (self.funding.is_some() as u8 * F_FUNDED)
            | (self.disclosure.is_some() as u8 * F_DISCLOSED)
            | (self.emergency as u8 * F_EMERGENCY);
        s[23..55].copy_from_slice(&self.root);
        s[55..87].copy_from_slice(&self.script_hash);
        if let Some(f) = self.funding {
            s[87..119].copy_from_slice(&f.txid);
            s[119..123].copy_from_slice(&f.vout.to_le_bytes());
            s[123..131].copy_from_slice(&f.value.to_le_bytes());
            s[131..167].copy_from_slice(&f.sweep_input);
        }
        if let Some(d) = self.disclosure {
            s[167..175].copy_from_slice(&d.round0);
            s[175..184].copy_from_slice(&d.round1);
            s[184..187].copy_from_slice(&d.picks);
            s[187..219].copy_from_slice(&d.binding);
            s[219..251].copy_from_slice(&d.digest);
        }
        s
    }

    /// `Ok(None)` for an empty slot; `StoreCorrupt` for anything this code didn't write.
    pub fn decode(s: &Slot) -> Result<Option<Record>> {
        if s.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        let flags = s[22];
        let state = State::from_byte(s[21]).ok_or(Error::StoreCorrupt)?;
        let funded = flags & F_FUNDED != 0;
        let disclosed = flags & F_DISCLOSED != 0;
        let consistent = s[0] == LAYOUT_V1
            && flags & !(F_FUNDED | F_DISCLOSED | F_EMERGENCY) == 0
            && s[251..].iter().all(|&b| b == 0)
            && (funded || s[87..167].iter().all(|&b| b == 0))
            && (disclosed || s[167..251].iter().all(|&b| b == 0))
            && (!disclosed || funded)
            && match state {
                State::Allocated => !disclosed,
                State::Exposed => disclosed,
                State::Retired | State::Unknown => true,
            };
        if !consistent {
            return Err(Error::StoreCorrupt);
        }
        let take = |r: core::ops::Range<usize>| &s[r];
        let arr32 = |r| -> [u8; 32] { take(r).try_into().unwrap_or([0; 32]) };
        Ok(Some(Record {
            wallet: take(1..17).try_into().unwrap_or([0; 16]),
            v: u32::from_be_bytes([s[17], s[18], s[19], s[20]]),
            state,
            emergency: flags & F_EMERGENCY != 0,
            root: arr32(23..55),
            script_hash: arr32(55..87),
            funding: funded.then(|| Funding {
                txid: arr32(87..119),
                vout: u32::from_le_bytes([s[119], s[120], s[121], s[122]]),
                value: u64::from_le_bytes(take(123..131).try_into().unwrap_or([0; 8])),
                sweep_input: take(131..167).try_into().unwrap_or([0; 36]),
            }),
            disclosure: disclosed.then(|| Disclosure {
                round0: take(167..175).try_into().unwrap_or([0; 8]),
                round1: take(175..184).try_into().unwrap_or([0; 9]),
                picks: take(184..187).try_into().unwrap_or([0; 3]),
                binding: arr32(187..219),
                digest: arr32(219..251),
            }),
        }))
    }
}

fn decode_namespaces(s: &Slot) -> Result<([Option<Namespace>; MAX_NAMESPACES], usize)> {
    let mut out = [None; MAX_NAMESPACES];
    if s.iter().all(|&b| b == 0) {
        return Ok((out, 0));
    }
    let count = s[1] as usize;
    if s[0] != LAYOUT_V1 || count > MAX_NAMESPACES {
        return Err(Error::StoreCorrupt);
    }
    let end = 2 + count * NS_ENTRY;
    if s[end..].iter().any(|&b| b != 0) {
        return Err(Error::StoreCorrupt);
    }
    for (k, slot) in out.iter_mut().enumerate().take(count) {
        let e = &s[2 + k * NS_ENTRY..2 + (k + 1) * NS_ENTRY];
        let state = match e[16] {
            1 => NsState::Fresh,
            2 => NsState::Unknown,
            _ => return Err(Error::StoreCorrupt),
        };
        *slot = Some(Namespace {
            wallet: e[..16].try_into().unwrap_or([0; 16]),
            state,
            next_v: u32::from_be_bytes([e[17], e[18], e[19], e[20]]),
        });
    }
    Ok((out, count))
}

fn encode_namespaces(list: &[Option<Namespace>; MAX_NAMESPACES]) -> Slot {
    let mut s = [0u8; SLOT_LEN];
    s[0] = LAYOUT_V1;
    let mut n = 0;
    for ns in list.iter().flatten() {
        let at = 2 + n * NS_ENTRY;
        s[at..at + 16].copy_from_slice(&ns.wallet);
        s[at + 16] = match ns.state {
            NsState::Fresh => 1,
            NsState::Unknown => 2,
        };
        s[at + 17..at + 21].copy_from_slice(&ns.next_v.to_be_bytes());
        n += 1;
    }
    s[1] = n as u8;
    s
}

/// Check every slot. Anything unreadable makes the whole store refuse.
pub fn verify<S: Store>(store: &S) -> Result<()> {
    decode_namespaces(store.read(0))?;
    for slot in 1..SLOTS {
        Record::decode(store.read(slot))?;
    }
    Ok(())
}

/// This wallet's namespace, with `next_v` raised past every recorded index.
pub fn namespace<S: Store>(store: &S, wallet: &[u8; 16]) -> Result<Option<Namespace>> {
    verify(store)?;
    let (list, _) = decode_namespaces(store.read(0))?;
    let Some(mut ns) = list.iter().flatten().find(|n| n.wallet == *wallet).copied() else {
        return Ok(None);
    };
    for slot in 1..SLOTS {
        if let Some(r) = Record::decode(store.read(slot))? {
            if r.wallet == *wallet && r.v >= ns.next_v {
                ns.next_v = r.v.saturating_add(1);
            }
        }
    }
    Ok(Some(ns))
}

pub fn set_namespace<S: Store>(store: &mut S, ns: Namespace) -> Result<()> {
    verify(store)?;
    let (mut list, count) = decode_namespaces(store.read(0))?;
    match list.iter_mut().flatten().find(|n| n.wallet == ns.wallet) {
        Some(existing) => *existing = ns,
        None => {
            if count == MAX_NAMESPACES {
                return Err(Error::StoreFull);
            }
            list[count] = Some(ns);
        }
    }
    store.write(0, &encode_namespaces(&list));
    Ok(())
}

/// The slot and record of `wallet`'s vault `v`.
pub fn find<S: Store>(store: &S, wallet: &[u8; 16], v: u32) -> Result<Option<(usize, Record)>> {
    verify(store)?;
    for slot in 1..SLOTS {
        if let Some(r) = Record::decode(store.read(slot))? {
            if r.wallet == *wallet && r.v == v {
                return Ok(Some((slot, r)));
            }
        }
    }
    Ok(None)
}

/// The `i`-th record of `wallet`, in slot order, for export.
pub fn nth<S: Store>(store: &S, wallet: &[u8; 16], i: usize) -> Result<Option<Record>> {
    verify(store)?;
    let mut k = 0;
    for slot in 1..SLOTS {
        if let Some(r) = Record::decode(store.read(slot))? {
            if r.wallet == *wallet {
                if k == i {
                    return Ok(Some(r));
                }
                k += 1;
            }
        }
    }
    Ok(None)
}

pub fn count<S: Store>(store: &S, wallet: &[u8; 16]) -> Result<usize> {
    verify(store)?;
    let mut k = 0;
    for slot in 1..SLOTS {
        if let Some(r) = Record::decode(store.read(slot))? {
            k += (r.wallet == *wallet) as usize;
        }
    }
    Ok(k)
}

/// Write `record` over its existing slot, or into a free one.
pub fn put<S: Store>(store: &mut S, record: &Record) -> Result<()> {
    let slot = match find(store, &record.wallet, record.v)? {
        Some((slot, _)) => slot,
        None => (1..SLOTS)
            .find(|&s| store.read(s).iter().all(|&b| b == 0))
            .ok_or(Error::StoreFull)?,
    };
    store.write(slot, &record.encode());
    Ok(())
}

/// Drop a record: only for a retired vault of a fresh namespace, whose index
/// stays reserved below `next_v`.
pub fn remove<S: Store>(store: &mut S, wallet: &[u8; 16], v: u32) -> Result<()> {
    if let Some((slot, _)) = find(store, wallet, v)? {
        store.write(slot, &[0u8; SLOT_LEN]);
    }
    Ok(())
}

/// Whether a free record slot exists.
pub fn has_room<S: Store>(store: &S) -> Result<bool> {
    verify(store)?;
    Ok((1..SLOTS).any(|s| store.read(s).iter().all(|&b| b == 0)))
}

/// What the device may do with `wallet`'s vault `v`, from its persistent state.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Standing {
    /// Never allocated by this device, in a fresh namespace.
    NotAllocated,
    /// Below `next_v` with no record: permanently unavailable.
    Reserved,
    /// No trustworthy history for this seed (namespace unknown or absent).
    NoHistory,
    Recorded(Record),
}

pub fn standing<S: Store>(store: &S, wallet: &[u8; 16], v: u32) -> Result<Standing> {
    if let Some((_, r)) = find(store, wallet, v)? {
        return Ok(Standing::Recorded(r));
    }
    Ok(match namespace(store, wallet)? {
        Some(Namespace {
            state: NsState::Fresh,
            next_v,
            ..
        }) => {
            if v < next_v {
                Standing::Reserved
            } else {
                Standing::NotAllocated
            }
        }
        _ => Standing::NoHistory,
    })
}

/// The status byte GET_VAULT reports.
pub fn status_byte(s: &Standing) -> u8 {
    match s {
        Standing::NotAllocated => 0,
        Standing::Recorded(r) => r.state.byte(),
        Standing::Reserved => 5,
        Standing::NoHistory => 6,
    }
}
