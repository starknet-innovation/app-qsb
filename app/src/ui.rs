//! Screens. Every value a review shows is derived on the device from bytes it
//! hashed into what it signs or records; nothing there is host-supplied text.

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
use pqb_core::address;
use pqb_core::amount::format_btc;
use pqb_core::deposit::{self, Kind};
use pqb_core::pqb::{fingerprint, MENU_WIDTHS, ROUND0, ROUND1, TABLE};
use pqb_core::signin::SignIn;
use pqb_core::withdraw::{self, Decision};

use crate::crypto::DeviceHashes;
use crate::AppSW;

#[cfg(target_os = "apex_p")]
const PQB: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/pqb_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const PQB: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/pqb_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const PQB: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/home_nano_nbgl.png", NBGL));

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const PQB_SMALL: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/pqb_14x14.gif", NBGL));
#[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
const PQB_SMALL: NbglGlyph = PQB;

const NETWORK: &str = "Bitcoin mainnet";
const HIGH_FEES: &str = "Fees are above 10%\nof the amount";

pub fn home() -> NbglHomeAndSettings {
    NbglHomeAndSettings::new()
        .glyph(&PQB)
        .tagline("Post-quantum Bitcoin\nvault secrets")
        .infos("PQB", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_AUTHORS"))
}

fn fingerprint_str(root: &[u8; 32]) -> String {
    String::from(core::str::from_utf8(&fingerprint(root)).unwrap_or(""))
}

/// The opening page of a generic review.
fn intent(title: &str, subtitle: &str) -> NbglPageContent {
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    let info = CenteredInfo::new(
        title,
        subtitle,
        "",
        Some(&PQB_SMALL),
        false,
        CenteredInfoStyle::LargeCaseBoldInfo,
        0,
    );
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    let info = CenteredInfo::new(
        title,
        subtitle,
        Some(&PQB_SMALL),
        false,
        CenteredInfoStyle::BoldText1Info,
    );
    NbglPageContent::CenteredInfo(info)
}

/// The closing page: a long press on touch screens. Nano has no long-press
/// page, so it gets a button, confirmed with both buttons like any approval.
fn hold(text: &str, touch: &str, nano: &str) -> NbglPageContent {
    #[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
    let page = {
        let _ = nano;
        NbglPageContent::InfoLongPress(ledger_device_sdk::nbgl::InfoLongPress::new(
            text,
            Some(&PQB_SMALL),
            touch,
            TuneIndex::Success,
        ))
    };
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    let page = {
        let _ = touch;
        NbglPageContent::InfoButton(InfoButton::new(
            text,
            Some(&PQB_SMALL),
            nano,
            TuneIndex::Success,
        ))
    };
    page
}

fn tag_values(fields: &[Field]) -> NbglPageContent {
    NbglPageContent::TagValueList(TagValueList::new(fields, 0, false, false))
}

/// What GET_VAULT's status byte means, for the screen.
fn status_text(status: u8) -> (&'static str, Option<&'static str>) {
    match status {
        1 => ("Allocated", None),
        2 => ("Disclosed", Some("Secrets disclosed: do not fund")),
        3 => ("Retired", Some("Retired: do not fund")),
        4 => ("Unknown", Some("Disclosed outside custody: do not fund")),
        5 => ("Reserved", Some("Unavailable: do not fund")),
        6 => ("No history on this device", Some("Not safe to fund")),
        _ => ("Not allocated", Some("Not allocated: do not fund")),
    }
}

/// "PQB vault #v", the network, the root's fingerprint and the vault's status,
/// for the user to compare with their records. Returns whether they confirmed.
pub fn verify_vault(comm: &mut Comm, v: u32, root: &[u8; 32], status: u8, funded: bool) -> bool {
    let fp = fingerprint_str(root);
    let number = format!("#{}", v);
    let title = format!("Verify PQB vault #{}", v);
    let (state, warning) = status_text(status);
    let mut fields = Vec::from([
        Field {
            name: "Vault",
            value: number.as_str(),
        },
        Field {
            name: "Network",
            value: NETWORK,
        },
        Field {
            name: "Fingerprint",
            value: fp.as_str(),
        },
        Field {
            name: "Status",
            value: state,
        },
    ]);
    let warning = match (warning, funded && status == 1) {
        (Some(w), _) => Some(w),
        (None, true) => Some("Already funded: do not fund again"),
        (None, false) => None,
    };
    if let Some(w) = warning {
        fields.push(Field {
            name: "Warning",
            value: w,
        });
    }
    NbglGenericReview::new()
        .add_content(intent(&title, "against your records"))
        .add_content(tag_values(&fields))
        .add_content(NbglPageContent::InfoButton(InfoButton::new(
            "Same fingerprint\nin your records?",
            Some(&PQB_SMALL),
            "OK",
            TuneIndex::Success,
        )))
        .show(comm, "Back")
}

/// The first allocation on a seed: has it ever held PQB vaults? `true` for a
/// first use. All in the message: Nano shows only a choice's first text.
pub fn first_use(comm: &mut Comm) -> bool {
    NbglChoice::new().glyph(&PQB_SMALL).show(
        comm,
        "First PQB vault\non this seed?",
        "Answer no if it ever held PQB vaults, on any device or app install",
        "Yes, first use",
        "No, used before",
    )
}

/// A seed with unknown history can't allocate: say so.
pub fn no_history(comm: &mut Comm) {
    let _ = NbglAction::new()
        .glyph(&PQB_SMALL)
        .message("No safe history\nUse a new\npassphrase")
        .action_text("Back")
        .show(comm);
}

/// Allocating vault `v`. Returns whether the user approved.
pub fn allocate(comm: &mut Comm, v: u32, root: &[u8; 32]) -> bool {
    let fp = fingerprint_str(root);
    let number = format!("#{}", v);
    let title = format!("Create PQB vault #{}", v);
    let fields = [
        Field {
            name: "Vault",
            value: number.as_str(),
        },
        Field {
            name: "Network",
            value: NETWORK,
        },
        Field {
            name: "Fingerprint",
            value: fp.as_str(),
        },
        Field {
            name: "Use",
            value: "One payment, one withdrawal",
        },
        Field {
            name: "Note",
            value: "Keep the fingerprint with your backup",
        },
    ];
    NbglGenericReview::new()
        .add_content(intent(&title, "Single use"))
        .add_content(tag_values(&fields))
        .add_content(NbglPageContent::InfoButton(InfoButton::new(
            "Create this vault?",
            Some(&PQB_SMALL),
            "Create",
            TuneIndex::Success,
        )))
        .show(comm, "Reject")
}

/// Retiring vault `v`. Returns whether the user confirmed.
pub fn retire(comm: &mut Comm, v: u32) -> bool {
    let question = format!("Retire vault #{}?\nIt can never\ndisclose again", v);
    NbglChoice::new()
        .glyph(&PQB_SMALL)
        .show(comm, &question, "", "Retire", "Cancel")
}

/// The deposit address of vault `v`, for the user to compare.
pub fn verify_deposit_address(comm: &mut Comm, v: u32, address: &str) -> bool {
    let number = format!("PQB vault #{}", v);
    let details = [
        Field {
            name: "Deposit for",
            value: number.as_str(),
        },
        Field {
            name: "Type",
            value: "Native SegWit, swept into the vault",
        },
    ];
    NbglAddressReview::new()
        .glyph(&PQB_SMALL)
        .review_title("Verify PQB\ndeposit address")
        .set_tag_value_list(&details)
        .show(comm, address)
}

/// A QSB sign-in challenge for vault `v`'s deposit address. Returns whether
/// the user approved it.
pub fn review_sign_in(
    comm: &mut Comm,
    sign_in: &SignIn,
    v: u32,
    root: &[u8; 32],
    address: &str,
) -> bool {
    let number = format!("#{}", v);
    let fp = fingerprint_str(root);
    let fields = [
        Field {
            name: "Origin",
            value: sign_in.origin,
        },
        Field {
            name: "Vault",
            value: number.as_str(),
        },
        Field {
            name: "Fingerprint",
            value: fp.as_str(),
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
        .glyph(&PQB_SMALL)
        .show(comm, &fields)
}

/// A sweep into the vault or a refund from its deposit address.
pub fn review_deposit(
    comm: &mut Comm,
    review: &deposit::Review,
    root: &[u8; 32],
) -> Result<bool, AppSW> {
    let fees = format_btc(review.fee);
    let fp = fingerprint_str(root);
    let vault = format!("PQB vault #{}", review.v);
    // Owned strings first: fields borrow them.
    let mut values: Vec<(String, String)> = Vec::new();
    let (title, finish) = match review.kind {
        Kind::Sweep => {
            values.push(("Amount".into(), format_btc(review.amount).as_str().into()));
            values.push(("To".into(), vault.clone()));
            values.push(("Fingerprint".into(), fp));
            (
                format!("Review transaction\nto fund PQB vault #{}", review.v),
                format!("Sign transaction\nto fund PQB vault #{}", review.v),
            )
        }
        Kind::Refund => {
            values.push(("From".into(), format!("Deposit of vault #{}", review.v)));
            for payee in review.payees.iter().flatten() {
                let amount = format_btc(payee.value);
                if payee.change {
                    values.push(("Change".into(), amount.as_str().into()));
                } else {
                    let to = address::from_script::<DeviceHashes>(payee.script.as_bytes())?;
                    values.push(("Amount".into(), amount.as_str().into()));
                    values.push(("To".into(), to.as_str().into()));
                }
            }
            (
                "Review transaction\nto refund a PQB deposit".into(),
                "Sign transaction\nto refund a PQB deposit".into(),
            )
        }
    };
    values.push(("Fees".into(), fees.as_str().into()));
    if review.high_fee {
        values.push(("High fees warning".into(), HIGH_FEES.into()));
    }
    let fields: Vec<Field> = values
        .iter()
        .map(|(n, v)| Field {
            name: n.as_str(),
            value: v.as_str(),
        })
        .collect();
    Ok(NbglReview::new()
        .tx_type(TransactionType::Transaction)
        .titles(&title, "", &finish)
        .glyph(&PQB_SMALL)
        .show(comm, &fields))
}

/// The disclosure review. Returns whether the user approved it.
pub fn review_withdrawal(
    comm: &mut Comm,
    review: &withdraw::Review,
    root: &[u8; 32],
    decision: Decision,
) -> Result<bool, AppSW> {
    let mut values: Vec<(String, String)> = Vec::new();
    values.push(("Vault".into(), format!("#{}", review.v)));
    values.push(("Fingerprint".into(), fingerprint_str(root)));
    values.push(("Network".into(), NETWORK.into()));
    let several = review.outputs.iter().flatten().count() > 1;
    for (i, (value, script)) in review.outputs.iter().flatten().enumerate() {
        let to = address::from_script::<DeviceHashes>(script.as_bytes())?;
        let suffix = if several {
            format!(" {}", i + 1)
        } else {
            String::new()
        };
        values.push((
            format!("Amount{}", suffix),
            format_btc(*value).as_str().into(),
        ));
        values.push((format!("To{}", suffix), to.as_str().into()));
    }
    values.push(("Fees".into(), format_btc(review.fee).as_str().into()));
    if review.high_fee {
        values.push(("High fees warning".into(), HIGH_FEES.into()));
    }
    values.push((
        "Discloses".into(),
        format!(
            "{} of {} secrets, {} menu signatures, co-signature",
            ROUND0 + ROUND1,
            TABLE,
            MENU_WIDTHS.len()
        ),
    ));
    values.push((
        "Binding".into(),
        "Classically bound, quantum-unverified".into(),
    ));
    if let Decision::Emergency { .. } = decision {
        values.push((
            "Warning".into(),
            "If a withdrawal was ever sent from another device or install, this one is fatal"
                .into(),
        ));
    }
    let retry = matches!(
        decision,
        Decision::Retry | Decision::Emergency { retry: true }
    );
    if retry {
        values.push(("Withdrawal".into(), "Retry of the recorded one".into()));
    } else {
        values.push(("Note".into(), "Final: no fee bump, no other spend".into()));
    }
    let fields: Vec<Field> = values
        .iter()
        .map(|(n, v)| Field {
            name: n.as_str(),
            value: v.as_str(),
        })
        .collect();

    let title = format!("Withdraw from\nPQB vault #{}", review.v);
    let mut flow = NbglGenericReview::new();
    if let Decision::Emergency { .. } = decision {
        flow = flow.add_content(intent("Outside custody\nconformance", "No safe history"));
    }
    Ok(flow
        .add_content(intent(&title, "One-time disclosure"))
        .add_content(tag_values(&fields))
        .add_content(hold("Disclose secrets?", "Hold to disclose", "Disclose"))
        .show(comm, "Reject"))
}

/// A different disclosure or funding is recorded: say so; nothing to approve.
pub fn conflict(comm: &mut Comm, v: u32) {
    let message = format!("Vault #{} already\nused for another\nwithdrawal", v);
    let _ = NbglAction::new()
        .glyph(&PQB_SMALL)
        .message(&message)
        .action_text("Back")
        .show(comm);
}

/// MENU_POINTS authorization for vault `v`.
pub fn authorize_menu_points(comm: &mut Comm, v: u32) -> bool {
    let question = format!("Export solver data\nfor vault #{}?", v);
    NbglChoice::new().glyph(&PQB_SMALL).show(
        comm,
        &question,
        "Keep it private to your solver",
        "Export",
        "Cancel",
    )
}

pub fn status(comm: &mut Comm, status_type: StatusType, success: bool) {
    NbglReviewStatus::new()
        .status_type(status_type)
        .show(comm, success);
}

pub fn message(comm: &mut Comm, text: &str, success: bool) {
    NbglStatus::new().text(text).show(comm, success);
}

/// Shown between approval and the last signature the host collects. NBGL keeps
/// a pointer to the text, so the caller keeps `spinner` alive.
pub fn signing(spinner: &mut NbglSpinner) {
    spinner.show("Signing transaction");
}

/// Shown between approval and the last chunk the host reads.
pub fn disclosing(spinner: &mut NbglSpinner) {
    spinner.show("Disclosing secrets");
}
