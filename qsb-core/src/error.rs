/// Every way a request can be refused. The app maps each to a status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The APDU payload has the wrong length or framing.
    BadLength,
    /// The BIP-32 path is not one this app derives (see `path`).
    BadPath,
    /// The command arrived out of order.
    BadState,
    /// A transaction or script could not be parsed.
    Parse,
    /// A previous transaction does not hash to the outpoint's txid.
    TxidMismatch,
    /// An input that must be the wallet's does not pay the wallet's script.
    NotOwnInput,
    /// A script that must be a QSB vault is not one.
    NotVault,
    /// The transaction is not a QSB deposit or withdrawal of the declared kind.
    BadLayout,
    /// An output the app cannot show as an address.
    UnsupportedOutput,
    /// Amounts overflow, or the fee is not positive.
    BadAmount,
    /// The message is not a QSB sign-in challenge for this address.
    BadMessage,
    /// The signature from the secure element is malformed.
    BadSignature,
    /// A HORS request is malformed: an index out of range or repeated, a bad length.
    BadData,
    /// A HORS request names a network this build doesn't serve.
    WrongNetwork,
    /// A different reveal is already recorded for this vault.
    RevealConflict,
    /// REVEAL_READ without an approved, unexpired REVEAL_PREPARE.
    NoApprovedReveal,
    /// The reveal guard's stored table is unreadable; reveals are refused.
    GuardCorrupt,
}

pub type Result<T> = core::result::Result<T, Error>;
