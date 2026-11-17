/// Every way a request can be refused. The app maps each to a status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The APDU payload has the wrong length or framing.
    BadLength,
    /// The command arrived out of order.
    BadState,
    /// A transaction could not be parsed.
    Parse,
    /// A previous transaction does not hash to the outpoint's txid.
    TxidMismatch,
    /// An input that must spend the vault's deposit address does not.
    NotOwnInput,
    /// A script that must be this vault's locking script is not.
    NotVault,
    /// The transaction does not have the layout its kind requires.
    BadLayout,
    /// An output the app cannot show as an address.
    UnsupportedOutput,
    /// Amounts overflow, or the fee is not positive.
    BadAmount,
    /// The signature from the secure element is malformed.
    BadSignature,
    /// A request field is out of range: a vault index, a table index, a menu pick.
    BadData,
    /// A different disclosure (or funding) is already recorded for this vault.
    Conflict,
    /// REVEAL_READ without an approved, unexpired disclosure.
    NoApprovedReveal,
    /// The persistent records are unreadable: allocations and disclosures are refused.
    StoreCorrupt,
    /// No room for another record or seed.
    StoreFull,
    /// The vault's recorded state does not allow this.
    VaultState,
    /// No trustworthy history for this seed: no allocation under custody conformance.
    Continuity,
    /// Menu points requested without the user's authorization for that vault.
    NotAuthorized,
}

pub type Result<T> = core::result::Result<T, Error>;
