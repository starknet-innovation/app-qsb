pub mod deposit;
pub mod vault;
pub mod withdraw;

use alloc::boxed::Box;

/// The multi-APDU operation in progress, if any. Any error ends it.
pub enum Session {
    Idle,
    Deposit(Box<deposit::DepositSession>),
    Withdraw(Box<withdraw::WithdrawSession>),
}
