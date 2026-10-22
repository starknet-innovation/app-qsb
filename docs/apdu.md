# QSB app APDU protocol

All commands use `CLA = 0xE0`. Integers are big-endian unless marked LE. A
BIP-32 path is serialized as `len (1) || element (4)…`. The app only accepts
5-element standard paths (see [Paths](#paths)).

| INS    | Command                                | P1                       | P2     |
| ------ | -------------------------------------- | ------------------------ | ------ |
| `0x01` | [HORS_GET_VERSION](#hors_get_version)  | `0x00`                   | `0x00` |
| `0x03` | [GET_VERSION](#get_version)            | `0x00`                   | `0x00` |
| `0x04` | [GET_APP_NAME](#get_app_name)          | `0x00`                   | `0x00` |
| `0x05` | [GET_WALLET_ADDRESS](#get_wallet_address) | `0x00` silent, `0x01` show on device | `0x00` |
| `0x06` | [SIGN_TX](#sign_tx)                    | step, see below          | `0x00` |
| `0x07` | [SIGN_IN](#sign_in)                    | `0x00` first, `0x80` more | `0x00` |
| `0x10` | [GET_COMMITMENTS](#get_commitments)    | round, `0x00` or `0x01`  | `0x00` |
| `0x11` | [GET_COMMITMENT_ROOT](#get_commitment_root) | `0x00` silent, `0x01` show on device | `0x00` |
| `0x20` | [REVEAL_PREPARE](#reveal_prepare)      | `0x00`                   | `0x00` |
| `0x21` | [REVEAL_READ](#reveal_read)            | chunk, `0x00` or `0x01`  | `0x00` |

`0x01` and `0x10`–`0x21` implement the QSB HORS spec ("QSB HORS Ledger App —
Specification", `QSB-HORS-v1`) and use its status words; see
[HORS secrets](#hors-secrets).

## Paths

The wallet is a single address, used by QSB for sign-in, deposits and the
withdrawal's helper input. The purpose fixes the address type:

| Path                                 | Address type            |
| ------------------------------------ | ----------------------- |
| `m/84'/0'/account'/change/index`     | P2WPKH (`bc1q…`)        |
| `m/49'/0'/account'/change/index`     | P2SH-P2WPKH (`3…`)      |

with `account ≤ 100'`, `change ∈ {0, 1}`, `index ≤ 50000`. Anything else is
refused with `0xB002`. The app is mainnet only.

## GET_VERSION

Response: `major (1) || minor (1) || patch (1)`.

## GET_APP_NAME

Response: the ASCII app name, `QSB`.

## GET_WALLET_ADDRESS

Data: `path`.

Response: `compressed public key (33) || address length (1) || address (ASCII)`.

With `P1 = 0x01` the address is shown for the user to compare and the response
is sent only once they confirm it (`0x6985` if they reject).

## SIGN_TX

Signs a QSB deposit or the wallet's helper input of a QSB withdrawal. The host
streams the unsigned transaction in order; the app hashes as it parses and
keeps only what the review and BIP-143 need. Each step is a separate APDU,
selected by `P1`:

| P1     | Step      | Data |
| ------ | --------- | ---- |
| `0x00` | START     | `kind (1) \|\| path \|\| version (4 LE) \|\| locktime (4 LE) \|\| input count (1) \|\| output count (1)` |
| `0x01` | INPUT     | `prev txid (32, serialization order) \|\| vout (4 LE) \|\| sequence (4 LE)` |
| `0x02` | PREVTX    | the next bytes (≤ 255) of the input's previous transaction, witness-stripped |
| `0x03` | OUTPUTS   | the next bytes (≤ 255) of the serialized outputs, without the output count |
| `0x04` | REVIEW    | empty |
| `0x05` | SIGN      | `input index (1)` |

`kind` is `0x01` for a deposit, `0x02` for a withdrawal.

Order: `START`, then for each input in order one `INPUT` followed by `PREVTX`
chunks until that previous transaction is complete, then `OUTPUTS` chunks until
every output is sent, then `REVIEW`, then one `SIGN` per input to sign.

Session rules:

- A new `START` discards any session.
- Any error ends the session, except a `SIGN` for an input that isn't signable
  (not the wallet's, or already signed), answered `0xB001` with the approved
  transaction kept.
- After approval the device shows "Signing transaction" until the last
  signable input is signed, then a status screen. Any command other than
  `SIGN` in between abandons the approved transaction.

**Previous transactions.** Every input's previous transaction is required, in
the legacy serialization (no SegWit marker, flag or witnesses). The app hashes it
and checks the result is the outpoint's txid, so the amount and script of the
spent output are proven rather than claimed. That is what makes the displayed
fee trustworthy: BIP-143 commits only to the signed input's own amount.

**Deposit** (`kind = 1`): 1–8 inputs, 1–2 outputs.

- Every input must spend the wallet's own address (the path's script).
- Output 0 must be a QSB vault script (see the README); its fingerprint and
  amount are shown.
- Output 1, if present, must pay the wallet's own address (change).
- Every input is signable.

**Withdrawal** (`kind = 2`): 2 inputs, 1 output.

- Input 0 must spend the wallet's own address (the helper UTXO).
- Input 1 must spend a QSB vault output. Its HORS scriptSig isn't sent: the
  helper's BIP-143 signature doesn't cover it.
- The output must be a standard address type (P2PKH, P2SH, P2WPKH, P2WSH or
  P2TR); its address, amount and the fee are shown.
- Only input 0 is signable.

The fee is `Σ inputs − Σ outputs` and must be positive.

`REVIEW` shows the transaction and answers `0x9000` once the user approves, or
`0x6985` if they reject. Fees above 10% of the value moved add a "High fees
warning" line to the review. `SIGN` then returns, once per signable input,
`DER signature || 0x01` (SIGHASH_ALL), the PSBT `partial_sig` value for the
wallet's public key. The signature is low-S.

## SIGN_IN

Signs QSB's sign-in challenge with BIP-322 (`POST /api/auth/challenge`). The app
signs no other message.

| P1     | Data |
| ------ | ---- |
| `0x00` | `path \|\| message length (2) \|\| message bytes…` |
| `0x80` | further message bytes |

The message is at most 512 bytes. After the last byte the app checks the
challenge (title, `Network: bitcoin-mainnet`, a UUID nonce, an ISO-8601 expiry,
the fixed footer, and `Address:` equal to the path's address), shows the origin,
address and expiry, and on approval returns `DER signature || 0x01` over the
BIP-322 `to_sign` transaction. Intermediate chunks answer `0x9000` with no data.

The host builds the BIP-322 "simple" encoding from it: the witness
`[signature, public key]`, serialized and base64-encoded. bip322-js, which
qsb-app's server uses, accepts it in strict mode for both address types.

The origin must be a web origin, `https://host[:port]` in lowercase (plain
`http` only for `localhost` or `127.0.0.1`), so nothing can hide in user info or
a path. The nonce must be a lowercase UUID.

## HORS secrets

The vault's 2 × 150 one-time HORS secrets can be derived on the device
instead of drawn from `os.urandom` by the QSB client. They are not tied to
any BIP-32 key:

```text
K          = SLIP-0021 key for the label "QSB-HORS" (declared in the app's install parameters)
s[v][r][i] = HMAC-SHA256(K, "QSB-HORS-v1" ‖ 0x00 ‖ net ‖ v ‖ r ‖ i)[0..20)
c[v][r][i] = RIPEMD160(SHA256(s))          the commitment qsb-app puts in the vault script
R[v]       = SHA256("QSB-HORS-v1/root" ‖ c[0][0..150) ‖ c[1][0..150))
```

`net` is `0x00` for mainnet (`0x01`, test networks, is refused by this
mainnet build with `0x6A92`), `v` the vault index (u32, below 2^31), `r` the
round (`0x00`, `0x01`) and `i` the index (u16, below 150). Integers are
big-endian. `K` is derived per command and wiped before the command returns.
[`tests/application_client/hors.py`](../tests/application_client/hors.py) is a
reference implementation.

### HORS_GET_VERSION

Response: `major (1) || minor (1) || patch (1) || "QSB-HORS-v1"`.

### GET_COMMITMENTS

P1 is the round. Data: `net (1) || v (4) || start (2) || count (1, 1–12)`,
with `start + count ≤ 150`. Response: `count` commitments of 20 bytes. No
approval: commitments are public. Reading a whole vault takes 13 commands per
round.

### GET_COMMITMENT_ROOT

Data: `net (1) || v (4)`. Response: `R (32)`. With `P1 = 0x01` the device first
shows "QSB vault #v", the network and the fingerprint (`R`'s first 8 bytes as
four groups of hex digits) for the user to compare with the QSB app, and a
warning not to fund the vault if this device already revealed its secrets;
`0x6985` if they go back.

### REVEAL_PREPARE

Data: `net (1) || v (4) || round 1 indices (8 × u16) || round 2 indices (7 × u16)
|| binding (32) || amount in sats (8) || destination script length (1) ||
destination script (≤ 34)`.

Checked before any screen, else `0x6A80`: indices below 150 and distinct within
a round, the exact length, an amount up to 21 million BTC, and a destination
the app can show as an address. `binding` is SHA-256 of the unsigned withdrawal
as the host serialises it; in v1 the device can't check it, or the amount and
destination, against the indices, so the review labels them host-reported.

The one-time reveal guard then decides, from the record of vaults this device
has revealed for (64 entries in NVM, oldest dropped first). A record is keyed
by wallet, network and vault index: the wallet is the tag
`HMAC-SHA256(K, "QSB-HORS-v1/guard")[0..8)`, so a BIP-39 passphrase's vaults
(another seed, other secrets) don't collide with the main seed's. If the stored
record is unreadable the device refuses every reveal (`0x6A93`) rather than
forget what it recorded.

| Record for (net, v) | Device |
| ------------------- | ------ |
| None | Shows the reveal. On approval it records `SHA256("QSB-HORS-v1/reveal" ‖ indices ‖ binding)`, durably, before answering. When the record is full, it first asks to forget the oldest vault, which lets that vault be revealed again. |
| Same reveal | Shows "Re-reveal QSB secrets": a failed broadcast can be retried. |
| A different reveal | Shows that the vault was already spent and answers `0x6A90`. No override. |

`0x9000` means approved: the preimages can be read.

### REVEAL_READ

P1 is the chunk. Response: chunk 0, preimages 1–12 (240 bytes); chunk 1,
preimages 13–15 (60 bytes), in the order the indices were sent, round 1 first.
Only after an approved REVEAL_PREPARE, and not after chunk 1 was read, the
approval timed out (60 seconds of the device's 100 ms ticker, which pauses
while another screen blocks), a new REVEAL_PREPARE arrived (even one refused
before any screen) or the app was closed: `0x6A91` otherwise. HORS_GET_VERSION
and REVEAL_READ take no data.

### HORS status words

| SW       | Meaning |
| -------- | ------- |
| `0x6A80` | Invalid data: index range, duplicate, length, destination |
| `0x6A86` | Wrong P1/P2 |
| `0x6A90` | A different reveal is recorded for this vault |
| `0x6A91` | REVEAL_READ without an approved REVEAL_PREPARE |
| `0x6A92` | Network not served by this build |
| `0x6A93` | The reveal record in NVM is unreadable; reveals are refused (an app extension to the spec) |
| `0x6985` | Rejected by the user |

## Status screens

After a review the device shows a status screen for about three seconds
("Transaction signed", "Message signed", "Address verified" or the rejection).
A command that arrives meanwhile is refused with `0x6901` without being
processed; resend it. The TypeScript client does.

## Status words

| SW       | Meaning |
| -------- | ------- |
| `0x9000` | Success |
| `0x6985` | Rejected by the user |
| `0x6A86` | Wrong P1/P2 |
| `0x6A87` | Wrong data length |
| `0x6D00` | Unknown INS |
| `0x6E00` | Wrong CLA |
| `0xB001` | Command out of order |
| `0xB002` | Path not accepted |
| `0xB003` | Transaction or script parse error |
| `0xB004` | Previous transaction doesn't match its txid |
| `0xB005` | An input that must be the wallet's isn't |
| `0xB006` | A script that must be a QSB vault isn't |
| `0xB007` | Not a QSB deposit or withdrawal layout |
| `0xB008` | Output can't be shown as an address |
| `0xB009` | Amount overflow or non-positive fee |
| `0xB00A` | Not a QSB sign-in challenge for this address |
| `0xB00B` | Signing failed |
| `0xB00C` | Key derivation failed |
| `0x6901` | Not accepted: a status screen is showing; resend |
