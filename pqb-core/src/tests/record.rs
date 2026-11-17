use crate::error::Error;
use crate::record::{
    self, Disclosure, Funding, Namespace, NsState, Record, Slot, Standing, State, Store, SLOTS,
    SLOT_LEN,
};

pub struct MemStore(pub [[u8; SLOT_LEN]; SLOTS]);

impl MemStore {
    pub fn new() -> Self {
        MemStore([[0; SLOT_LEN]; SLOTS])
    }
}

impl Store for MemStore {
    fn read(&self, slot: usize) -> &Slot {
        &self.0[slot]
    }
    fn write(&mut self, slot: usize, data: &Slot) {
        self.0[slot] = *data;
    }
}

const W: [u8; 16] = [0xaa; 16];

pub fn rec(v: u32, state: State) -> Record {
    let funded = state != State::Allocated;
    Record {
        wallet: W,
        v,
        state,
        emergency: false,
        root: [v as u8; 32],
        script_hash: [!(v as u8); 32],
        funding: funded.then_some(Funding {
            txid: [5; 32],
            vout: 1,
            value: 99_000,
            sweep_input: [6; 36],
        }),
        disclosure: (state == State::Exposed).then_some(Disclosure {
            round0: [0, 1, 2, 3, 4, 5, 6, 7],
            round1: [100, 101, 102, 103, 104, 105, 106, 107, 108],
            picks: [11, 0, 15],
            binding: [8; 32],
            digest: [9; 32],
        }),
    }
}

#[test]
fn encode_decode_roundtrip() {
    for state in [
        State::Allocated,
        State::Exposed,
        State::Retired,
        State::Unknown,
    ] {
        let r = rec(7, state);
        assert_eq!(Record::decode(&r.encode()), Ok(Some(r)));
        let e = Record {
            emergency: true,
            ..r
        };
        assert_eq!(Record::decode(&e.encode()), Ok(Some(e)));
    }
    assert_eq!(Record::decode(&[0; SLOT_LEN]), Ok(None));
}

#[test]
fn unreadable_slots_fail_closed() {
    let good = rec(1, State::Exposed).encode();
    // Every single-byte corruption of a meaningful field is either detected or
    // changes only data; layout, state and flag bytes are always checked.
    for (at, value) in [(0, 2u8), (21, 0), (21, 5), (22, 0x08), (22, 0x00), (255, 1)] {
        let mut bad = good;
        bad[at] = value;
        assert_eq!(Record::decode(&bad), Err(Error::StoreCorrupt), "byte {at}");
    }
    // An allocated record can't carry a disclosure.
    let mut bad = rec(1, State::Allocated).encode();
    bad[22] = 0x03;
    assert_eq!(Record::decode(&bad), Err(Error::StoreCorrupt));
    // One corrupt slot anywhere stops everything.
    let mut s = MemStore::new();
    record::put(&mut s, &rec(0, State::Allocated)).unwrap();
    s.0[17] = [0xff; SLOT_LEN];
    assert_eq!(record::find(&s, &W, 0).err(), Some(Error::StoreCorrupt));
    assert_eq!(record::namespace(&s, &W).err(), Some(Error::StoreCorrupt));
    let mut s = MemStore::new();
    s.0[0][0] = 9;
    assert_eq!(record::verify(&s).err(), Some(Error::StoreCorrupt));
}

#[test]
fn allocation_high_water_mark() {
    let mut s = MemStore::new();
    assert_eq!(record::namespace(&s, &W), Ok(None));
    assert_eq!(record::standing(&s, &W, 0), Ok(Standing::NoHistory));
    record::set_namespace(
        &mut s,
        Namespace {
            wallet: W,
            state: NsState::Fresh,
            next_v: 0,
        },
    )
    .unwrap();
    assert_eq!(record::standing(&s, &W, 0), Ok(Standing::NotAllocated));
    // A crash after writing the record but before raising next_v still counts it.
    record::put(&mut s, &rec(0, State::Allocated)).unwrap();
    assert_eq!(record::namespace(&s, &W).unwrap().unwrap().next_v, 1);
    assert_eq!(
        record::standing(&s, &W, 0),
        Ok(Standing::Recorded(rec(0, State::Allocated)))
    );
    // Removing a retired record leaves its index reserved.
    record::set_namespace(
        &mut s,
        Namespace {
            wallet: W,
            state: NsState::Fresh,
            next_v: 1,
        },
    )
    .unwrap();
    record::remove(&mut s, &W, 0).unwrap();
    assert_eq!(record::standing(&s, &W, 0), Ok(Standing::Reserved));
    assert_eq!(record::standing(&s, &W, 1), Ok(Standing::NotAllocated));
    // Another wallet's records and namespace are separate.
    let other = [0xbb; 16];
    assert_eq!(record::standing(&s, &other, 0), Ok(Standing::NoHistory));
    assert_eq!(record::count(&s, &other), Ok(0));
}

#[test]
fn storage_exhaustion_refuses() {
    let mut s = MemStore::new();
    for v in 0..record::CAPACITY as u32 {
        record::put(&mut s, &rec(v, State::Allocated)).unwrap();
    }
    assert_eq!(record::has_room(&s), Ok(false));
    assert_eq!(
        record::put(&mut s, &rec(99, State::Allocated)).err(),
        Some(Error::StoreFull)
    );
    // Updating an existing record still works.
    record::put(&mut s, &rec(3, State::Exposed)).unwrap();
    assert_eq!(record::nth(&s, &W, 3), Ok(Some(rec(3, State::Exposed))));
    assert_eq!(record::count(&s, &W), Ok(record::CAPACITY));
    for k in 0..record::MAX_NAMESPACES as u8 {
        record::set_namespace(
            &mut s,
            Namespace {
                wallet: [k; 16],
                state: NsState::Unknown,
                next_v: 0,
            },
        )
        .unwrap();
    }
    assert_eq!(
        record::set_namespace(
            &mut s,
            Namespace {
                wallet: [0xee; 16],
                state: NsState::Fresh,
                next_v: 0,
            }
        )
        .err(),
        Some(Error::StoreFull)
    );
}
