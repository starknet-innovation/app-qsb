# Changelog

## Unreleased

- SIGN_IN (`0x31`): signs the QSB sign-in challenge with BIP-322 as a vault's
  deposit address, so that address can sign in to qsb-app. Template only, as in
  0.1.0, but keyed by vault instead of BIP-32 path; the review shows the origin,
  vault number, fingerprint, address and expiry. Allowed in any vault state;
  records nothing. The TypeScript client's `signIn` returns the BIP-322
  "simple" signature.

## 0.2.0 (2026-11-18)

Retargeted from QSB to PQB, following the BIP draft "PQB Vault Secret
Management" 0.2.0. Not compatible with 0.1.0: the app is now `PQB`.

- Vault seeds derive from the device seed through BIP 85
  (`m/83696968'/39'/0'/24'/v'`) and the BIP's `PQB-v1` profile: 109 table
  entries, three signature menus, the ECDSA co-signing key and the deposit key,
  matching pqb's construction version `v1` (commit `82c7cba`; seed binding
  `pqb/vault-seed|hybrid|PQB|v1|real|main`, pinning menu `r = 1`). Every
  `main` vector of the BIP is a host test. The SLIP-0021 `QSB-HORS-v1`
  derivation is removed; vaults created with it are not recoverable by this version.
- The device embeds pqb's 4,696-byte vault script template and builds each
  vault's exact script; GET_SCRIPT exports it.
- Persistent allocation and disclosure records (`allocated`, `exposed`,
  `retired`, `unknown`) with a high-water mark per seed, replacing the 64-entry
  reveal guard and its eviction. Unreadable state fails closed.
- Withdrawals: one input, `T` rebuilt on the device, `B` and `D` per the BIP,
  exact retries only, and the device's own co-signature (legacy SIGHASH_ALL,
  RFC 6979, low S). Reviews label the binding as classically bound,
  quantum-unverified; an emergency path for seeds without history is labelled
  as outside custody conformance.
- Deposit addresses, the sweep that funds a vault (one funding per vault) and
  refunds, signed with the vault's deposit key.
- Menu-point export for the solver, after user authorization, and each stage's
  `r` (MENU_POINTS `P1 = 0x02`).
- Allocation applies the BIP's DER screen and skips any index whose vault has
  a commitment that parses as a strict DER signature.
- Conformance: the app claims derivation compatibility. Custody conformance
  needs the BIP's host-side vault directory, journal, chain checks and
  restoration flow, which neither client implements yet.
- Removed: BIP-84/49 wallet signing, QSB deposit and helper-input signing, and
  the QSB sign-in. New APDUs throughout (docs/apdu.md).
- TypeScript client renamed `@pqb/ledger`, with disclosure verification and
  device record parsing. The BIP's 0.1.0 recovery manifest is gone: 0.2.0
  keeps state in a per-vault directory instead.
- Python package `pqb_ledger` (clients/python): device-held pqb vaults, solver
  export and spend assembly through unmodified pqb, pinned to commit `82c7cba`.

## 0.1.0

- First version: clear-signs QSB vault deposits, withdrawal helper inputs and sign-in challenges on Nano S+, Nano X, Stax, Flex and Apex P.
- HORS secrets (spec QSB-HORS-v1) derived with SLIP-0021, revealed once per vault.
