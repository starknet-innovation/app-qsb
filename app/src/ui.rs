//! Screens. Every value a signing review shows is derived on the device from
//! bytes it has hashed into what it signs; nothing there is taken from the host
//! as display text. The HORS reveal is the exception the spec allows in v1: its
//! amount and destination are the host's word, and the screen says so.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{
    CenteredInfo, CenteredInfoStyle, Field, InfoButton, NbglAction, NbglAddressReview, NbglChoice,
    NbglGenericReview, NbglGlyph, NbglHomeAndSettings, NbglPageContent, NbglReview,
    NbglReviewStatus, NbglSpinner, NbglStatus, StatusType, TagValueList, TransactionType,
    TuneIndex,
};
use qsb_core::address;
use qsb_core::amount::format_btc;
use qsb_core::hors::{self, RevealRequest, Vault, NET_MAINNET, REVEALED, ROUNDS};
use qsb_core::session::{Kind, Review};
use qsb_core::signin::SignIn;

use crate::crypto::DeviceHashes;
use crate::AppSW;

#[cfg(target_os = "apex_p")]
const QSB: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/qsb_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const QSB: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/qsb_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const QSB: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl.png", NBGL));

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const QSB_SMALL: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/qsb_14x14.gif", NBGL));
#[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
const QSB_SMALL: NbglGlyph = QSB;

pub fn home() -> NbglHomeAndSettings {
    NbglHomeAndSettings::new()
        .glyph(&QSB)
        .tagline("QSB vault deposits,\nwithdrawals and secrets")
        .infos("QSB", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_AUTHORS"))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A vault fingerprint as qsb-app shows it: SHA-256 of the script, lowercase hex.
fn fingerprint(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

const HIGH_FEES: &str = "Fees are above 10%\nof the amount";

/// Show a QSB deposit or withdrawal. Returns whether the user approved it.
pub fn review_tx(comm: &mut Comm, review: &Review) -> Result<bool, AppSW> {
    let vault = fingerprint(&review.vault);
    let amount = format_btc(review.amount);
    let fees = format_btc(review.fee);

    let destination = match review.destination {
        Some(script) => Some(address::from_script::<DeviceHashes>(script.as_bytes())?),
        None => None,
    };

    // Field order follows Ledger's guidelines: from, amount, to, fees.
    let mut fields = Vec::with_capacity(5);
    let (title, finish) = match (review.kind, &destination) {
        (Kind::Deposit, _) => {
            fields.push(Field {
                name: "Amount",
                value: amount.as_str(),
            });
            fields.push(Field {
                name: "To vault",
                value: vault.as_str(),
            });
            (
                "Review transaction\nto deposit to a QSB vault",
                "Sign transaction\nto deposit to a QSB vault",
            )
        }
        (Kind::Withdrawal, Some(to)) => {
            fields.push(Field {
                name: "From vault",
                value: vault.as_str(),
            });
            fields.push(Field {
                name: "Amount",
                value: amount.as_str(),
            });
            fields.push(Field {
                name: "To",
                value: to.as_str(),
            });
            (
                "Review transaction\nto withdraw from a QSB vault",
                "Sign transaction\nto withdraw from a QSB vault",
            )
        }
        (Kind::Withdrawal, None) => return Err(AppSW::UnsupportedOutput),
    };
    fields.push(Field {
        name: "Fees",
        value: fees.as_str(),
    });
    if review.high_fee {
        fields.push(Field {
            name: "High fees warning",
            value: HIGH_FEES,
        });
    }

    Ok(NbglReview::new()
        .tx_type(TransactionType::Transaction)
        .titles(title, "", finish)
        .glyph(&QSB_SMALL)
        .show(comm, &fields))
}

/// Show a QSB sign-in challenge. Returns whether the user approved it.
pub fn review_sign_in(comm: &mut Comm, sign_in: &SignIn, address: &str) -> bool {
    let fields = [
        Field {
            name: "Origin",
            value: sign_in.origin,
        },
        Field {
            name: "Address",
            value: address,
        },
        Field {
            name: "Expires",
            value: sign_in.expires,
        },
    ];
    NbglReview::new()
        .tx_type(TransactionType::Message)
        .titles(
            "Review message\nto sign in to QSB",
            "",
            "Sign message\nto sign in to QSB",
        )
        .glyph(&QSB_SMALL)
        .show(comm, &fields)
}

/// Show the wallet address for the user to compare. Returns whether they confirmed it.
pub fn verify_address(comm: &mut Comm, address: &str) -> bool {
    NbglAddressReview::new()
        .glyph(&QSB_SMALL)
        .review_title("Verify QSB\nwallet address")
        .show(comm, address)
}

pub fn status(comm: &mut Comm, status_type: StatusType, success: bool) {
    NbglReviewStatus::new()
        .status_type(status_type)
        .show(comm, success);
}

/// Shown between approval and the last signature the host collects. NBGL keeps
/// a pointer to the text, so the caller keeps `spinner` alive.
pub fn signing(spinner: &mut NbglSpinner) {
    spinner.show("Signing transaction");
}

// --- QSB-HORS-v1 -------------------------------------------------------------

fn network(net: u8) -> &'static str {
    if net == NET_MAINNET {
        "Bitcoin mainnet"
    } else {
        "Bitcoin test network"
    }
}

/// The opening page of a generic review.
fn intent(title: &str, subtitle: &str) -> NbglPageContent {
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    let info = CenteredInfo::new(
        title,
        subtitle,
        "",
        Some(&QSB_SMALL),
        false,
        CenteredInfoStyle::LargeCaseBoldInfo,
        0,
    );
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    let info = CenteredInfo::new(
        title,
        subtitle,
        Some(&QSB_SMALL),
        false,
        CenteredInfoStyle::BoldText1Info,
    );
    NbglPageContent::CenteredInfo(info)
}

/// The closing page: a long press on touch screens. Nano has no long-press
/// page, so it gets a button, confirmed with both buttons like any approval.
fn hold_to_reveal(text: &str) -> NbglPageContent {
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    let page = NbglPageContent::InfoLongPress(ledger_device_sdk::nbgl::InfoLongPress::new(
        text,
        Some(&QSB_SMALL),
        "Hold to reveal",
        TuneIndex::Success,
    ));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    let page = NbglPageContent::InfoButton(InfoButton::new(
        text,
        Some(&QSB_SMALL),
        "Reveal",
        TuneIndex::Success,
    ));
    page
}

/// "QSB vault #v", the network and the commitment root's fingerprint, for the
/// user to compare with the QSB app. Returns whether they confirmed ("OK") or
/// went back. A review, not a choice page: Nano shows only a choice's first line.
/// `revealed`: this device already revealed the vault's secrets, so it must not
/// be funded (whoever saw the preimages could spend it).
pub fn hors_fingerprint(comm: &mut Comm, vault: Vault, root: &[u8; 32], revealed: bool) -> bool {
    let fingerprint = hors::fingerprint(root);
    let number = format!("#{}", vault.index);
    let title = format!("Verify vault #{}", vault.index);
    let mut fields = Vec::from([
        Field {
            name: "Vault",
            value: number.as_str(),
        },
        Field {
            name: "Network",
            value: network(vault.net),
        },
        Field {
            name: "Fingerprint",
            value: core::str::from_utf8(&fingerprint).unwrap_or(""),
        },
    ]);
    if revealed {
        fields.push(Field {
            name: "Warning",
            value: "Secrets already revealed: do not fund",
        });
    }
    NbglGenericReview::new()
        .add_content(intent(&title, "against the QSB app"))
        .add_content(NbglPageContent::TagValueList(TagValueList::new(
            &fields, 0, false, false,
        )))
        .add_content(NbglPageContent::InfoButton(InfoButton::new(
            "Same fingerprint\nin the QSB app?",
            Some(&QSB_SMALL),
            "OK",
            TuneIndex::Success,
        )))
        .show(comm, "Back")
}

/// The reveal review. Returns whether the user approved it.
pub fn hors_reveal(comm: &mut Comm, request: &RevealRequest, again: bool) -> Result<bool, AppSW> {
    let vault = format!("#{}", request.vault.index);
    let subtitle = format!("of vault #{}", request.vault.index);
    let amount = format_btc(request.amount);
    let to = address::from_script::<DeviceHashes>(request.destination.as_bytes())?;
    let revealed = format!("{} of {}", REVEALED, ROUNDS * hors::N);
    let fields: Vec<Field> = if again {
        Vec::from([
            Field {
                name: "Vault",
                value: vault.as_str(),
            },
            Field {
                name: "Withdrawal",
                value: "Same withdrawal as before",
            },
        ])
    } else {
        Vec::from([
            Field {
                name: "Vault",
                value: vault.as_str(),
            },
            Field {
                name: "Network",
                value: network(request.vault.net),
            },
            Field {
                name: "Amount",
                value: amount.as_str(),
            },
            Field {
                name: "To",
                value: to.as_str(),
            },
            Field {
                name: "Warning",
                value: "Amount and To are host-reported, not verified",
            },
            Field {
                name: "Secrets revealed",
                value: revealed.as_str(),
            },
            Field {
                name: "Note",
                value: "This vault can be spent only once",
            },
        ])
    };
    let (title, finish) = if again {
        ("Re-reveal QSB secrets", "Re-reveal QSB secrets?")
    } else {
        ("Reveal QSB secrets", "Reveal QSB secrets?")
    };
    Ok(NbglGenericReview::new()
        .add_content(intent(title, &subtitle))
        .add_content(NbglPageContent::TagValueList(TagValueList::new(
            &fields, 0, false, false,
        )))
        .add_content(hold_to_reveal(finish))
        .show(comm, "Reject"))
}

/// A different reveal is recorded for this vault: say so; nothing to approve.
pub fn hors_conflict(comm: &mut Comm, vault: Vault) {
    let message = format!(
        "Vault #{} already spent\nwith a different withdrawal",
        vault.index
    );
    let _ = NbglAction::new()
        .glyph(&QSB_SMALL)
        .message(&message)
        .action_text("Back")
        .show(comm);
}

/// The guard is full: ask to forget its oldest vault, which lets that vault be
/// revealed again. `other_wallet`: the record belongs to another seed on this
/// device (a passphrase). Returns whether to go on.
pub fn hors_forget(comm: &mut Comm, oldest: Vault, other_wallet: bool) -> bool {
    // All in the message: Nano shows only a choice's first text.
    let whose = if other_wallet {
        "another wallet's "
    } else {
        ""
    };
    let question = format!(
        "Reveal history full\nForget {}vault #{}?",
        whose, oldest.index
    );
    NbglChoice::new()
        .glyph(&QSB_SMALL)
        .show(comm, &question, "", "Forget", "Cancel")
}

/// Shown between approval and the last preimage chunk the host reads.
pub fn revealing(spinner: &mut NbglSpinner) {
    spinner.show("Revealing secrets");
}

pub fn hors_status(comm: &mut Comm, success: bool) {
    let text = if success {
        "QSB secrets revealed"
    } else {
        "Reveal rejected"
    };
    NbglStatus::new().text(text).show(comm, success);
}
