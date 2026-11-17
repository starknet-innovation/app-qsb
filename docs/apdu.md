# PQB app APDU protocol

All commands use `CLA = 0xE0`. Integers are big-endian unless marked LE. A
vault is named by its index `v` (4 bytes, below 2^31). The app serves Bitcoin
mainnet only (`net = main`), and derives every vault from the device seed with
the BIP's `bip85` source and the `PQB-v1` profile, which targets pqb's
construction version `v1` (see the README).

| INS    | Command                                         | P1                                   | P2     |
| ------ | ----------------------------------------------- | ------------------------------------ | ------ |
| `0x03` | [GET_VERSION](#get_version)                     | `0x00`                               | `0x00` |
| `0x04` | [GET_APP_NAME](#get_app_name)                   | `0x00`                               | `0x00` |
| `0x10` | [GET_COMMITMENTS](#get_commitments)             | `0x00`                               | `0x00` |
| `0x11` | [GET_VAULT](#get_vault)                         | `0x00` silent, `0x01` show on device | `0x00` |
| `0x12` | [GET_SCRIPT](#get_script)                       | `0x00`                               | `0x00` |
| `0x13` | [GET_DEPOSIT_ADDRESS](#get_deposit_address)     | `0x00` silent, `0x01` show on device | `0x00` |
| `0x14` | [GET_STATE](#get_state)                         | `0x00` summary, `0x01` one record    | `0x00` |
| `0x20` | [ALLOCATE](#allocate)                           | `0x00`                               | `0x00` |
| `0x21` | [RETIRE](#retire)                               | `0x00`                               | `0x00` |
| `0x30` | [SIGN_DEPOSIT](#sign_deposit)                   | step                                 | `0x00` |
| `0x40` | [WITHDRAW](#withdraw)                           | step                                 | `0x00` |
| `0x41` | [REVEAL_READ](#reveal_read)                     | chunk `0x00`–`0x04`                  | `0x00` |
| `0x42` | [MENU_POINTS](#menu_points)                     | `0x00` authorize, `0x01` read, `0x02` stage `r` | `0x00` |

## Conformance

The app claims **custody conformance** within one install's history: it is the
single authoritative writer for each seed it holds, records allocations and
disclosures in NVM before publishing a script or releasing anything, and fails
closed on unreadable state. Its continuity guarantee ends with any of: an app
update or reinstall (Ledger erases the app's NVM), a device reset, or the same
seed on another device or app. After that the seed has no trustworthy history
on the device (see [State](#state)).

It does **not** verify the three PQB puzzle solutions. Every disclosure is a
**classically bound, quantum-unverified transaction binding**: the co-signature
binds it to the displayed transaction against anyone who can't forge ECDSA, not
against a quantum adversary, and the review says so.

## GET_VERSION

Response: `major (1) || minor (1) || patch (1) || "PQB-v1"`.

## GET_APP_NAME

Response: the ASCII app name, `PQB`.

## GET_COMMITMENTS

Data: `v (4) || start (1) || count (1)`, `1 ≤ count ≤ 12`, `start + count ≤ 154`.

Response: `count × 20` bytes, commitments `start..start + count` in root order:
`c[0..109]`, `m_pin[0..12]`, `m_round0[0..16]`, `m_round1[0..16]`, `q`.

Read-only and allowed for any index: a result is not safe to fund unless
[GET_VAULT](#get_vault) reports the vault allocated.

## GET_VAULT

Data: `v (4)`.

Response: `R (32) || script hash (32) || status (1) || funded (1)`.

`R` is the commitment root, the script hash is SHA-256 of the vault's
4,696-byte locking script. `status`:

| Byte | Meaning |
| ---- | ------- |
| `0` | not allocated by this device (in a seed with history) |
| `1` | allocated |
| `2` | exposed: a disclosure is recorded |
| `3` | retired |
| `4` | unknown: disclosed on the emergency path |
| `5` | reserved: below the high-water mark, no record (retired and dropped) |
| `6` | no history: this seed has no trustworthy record on this device |

`funded` is `1` when a funding output is recorded.

With `P1 = 0x01` the device shows the vault number, the root's fingerprint
(first 8 bytes in four groups, e.g. `6c37 5dd4 d49e 27a6`) and its status, with
a warning unless it is allocated and open for funding. `0x6985` if rejected.

## GET_SCRIPT

Data: `v (4) || offset (2)`, `offset < 4696`.

Response: bytes `offset..min(offset + 250, 4696)` of the vault's locking script.

## GET_DEPOSIT_ADDRESS

Data: `v (4)`.

Response: `compressed public key (33) || address length (1) || address (ASCII)`,
the P2WPKH address of the vault's deposit key `dd`.

With `P1 = 0x01` the address is shown for comparison, and only for a vault that
is allocated, never disclosed and not yet funded (`0x6A94` otherwise).

## GET_STATE

`P1 = 0x00`, no data. Response:
`wallet id (16) || namespace (1) || next_v (4) || records (1) || capacity (1)`.

The wallet id is `SHA256("PQB-v1/wallet" || S(v = 0))[0..16)`, naming the seed
(a BIP-39 passphrase gives another). `namespace` is `0` none, `1` fresh, `2`
unknown. `records` counts this seed's records. In an unknown namespace,
emergency records can have `v >= next_v`; a manifest's `next_v` must then be
raised past every recorded index.

`P1 = 0x01`, data `i (1)`: the `i`-th record of this seed, 251 bytes, as stored
(without the slot's 5 bytes of zero padding):

```text
0x01 || wallet id (16) || v (4) || state (1) || flags (1) || R (32) || script hash (32)
|| funding txid (32, serialization order) || vout (4 LE) || value (8 LE) || sweep input (36)
|| round0 (8) || round1 (9) || picks (3) || B (32) || D (32)
```

`sweep input` is one outpoint (`txid || vout LE`) spent by the sweep that funded
the vault (see [SIGN_DEPOSIT](#sign_deposit)); zero when the funding was first
learned from a withdrawal. Unused fields are zero.

`state`: `1` allocated, `2` exposed, `3` retired, `4` unknown. `flags`: `0x01`
funded, `0x02` disclosure recorded, `0x04` emergency. A host builds the BIP's
portable recovery manifest from these and from GET_SCRIPT.

## ALLOCATE

No data. Response: `v (4) || R (32) || script hash (32)`.

Reserves the next index `v = next_v` for a new vault. If this seed has no
namespace on the device yet, the device first asks whether the seed has ever
held PQB vaults (on any device or app install):

- **Never used**: the namespace starts fresh at `next_v = 0`.
- **Used before**: the namespace is marked unknown and the allocation refused
  (`0x6A95`): without its history the device can't tell which indices are safe.
  New deposits need a fresh root, such as a new BIP-39 passphrase.

The device then shows the vault number and fingerprint; on approval it records
the vault `allocated`, raises `next_v` durably, and only then responds. `0x6A96`
when the record table is full, `0x6A95` in an unknown namespace.

## RETIRE

Data: `v (4)`. The device asks for confirmation, then marks the vault retired:
it can never disclose again, not even an exact retry. In a fresh namespace the
record is then dropped (its index stays reserved below `next_v`), freeing room.

## SIGN_DEPOSIT

Signs with a vault's deposit key: the **sweep** that funds the vault, or a
**refund** from the deposit address. Every input must spend the deposit
address; each previous transaction is streamed and hashed to its txid, so
amounts are proven. Each step is an APDU, selected by `P1`:

| P1     | Step    | Data |
| ------ | ------- | ---- |
| `0x00` | START   | `kind (1) \|\| v (4) \|\| version (4 LE) \|\| locktime (4 LE) \|\| inputs (1) \|\| outputs (1)` |
| `0x01` | INPUT   | `prev txid (32, serialization order) \|\| vout (4 LE) \|\| sequence (4 LE)` |
| `0x02` | PREVTX  | the next bytes (≤ 255) of the input's previous transaction, witness-stripped |
| `0x03` | OUTPUTS | the next bytes (≤ 255) of the serialized outputs, without their count |
| `0x04` | REVIEW  | empty |
| `0x05` | SIGN    | `input index (1)` → `DER signature || 0x01` |

`kind` `0x01` sweep: 1–8 inputs, exactly one output, which must be this vault's
locking script (compared by SHA-256 with the script the device derives). The
vault must be allocated and never disclosed. A vault takes one funding: a sweep
with another txid is accepted only if it spends an input of the recorded sweep,
so at most one can confirm (`0x6A90` otherwise). On approval the funding output
(txid, 0, value) is recorded before any signature is returned.

`kind` `0x02` refund: 1–8 inputs, one or two outputs to P2PKH, P2SH, P2WPKH,
P2WSH or P2TR addresses, one of which may return change to the deposit address.
Allowed in any vault state, so payments made after a sweep can be recovered.

Order: START, then for each input one INPUT followed by PREVTX chunks until
its previous transaction is complete, then OUTPUTS chunks, REVIEW, and one SIGN
per input. Signatures are BIP-143, SIGHASH_ALL, RFC 6979, low S. A new START
discards a session; any error ends it, except a SIGN of an input already
signed (`0xB001`), and any other command while signatures are collected ends it.

## WITHDRAW

One disclosure of a vault's secrets and the co-signature, for one withdrawal
transaction `T` with exactly one input, the vault output. Steps, by `P1`:

| P1     | Step    | Data |
| ------ | ------- | ---- |
| `0x00` | START   | `v (4) \|\| version (4 LE) \|\| prev txid (32, serialization order) \|\| vout (4 LE) \|\| sequence (4 LE) \|\| locktime (4 LE) \|\| outputs (1) \|\| round0 (8) \|\| round1 (9) \|\| picks (3)` |
| `0x01` | PREVTX  | the next bytes (≤ 255) of the transaction that created the vault output, witness-stripped |
| `0x02` | OUTPUTS | the next bytes (≤ 255) of `T`'s serialized outputs, without their count |
| `0x03` | REVIEW  | empty |

START is checked before anything else: exactly 8 round-0 and 9 round-1 table
indices in `[0, 108]`, strictly ascending within each round, none in both;
`p0 < 12`, `p1 < 16`, `p2 < 16`. Otherwise `0x6A80`. `T` must have 1–4
outputs (`0xB007` otherwise).

The previous transaction must hash to the outpoint and its output `vout` must be
vault `v`'s script (`0xB006` otherwise). Each output of `T` must be a standard
address with a nonzero amount, and the fee (vault value minus outputs) positive.

From these fields the device builds `T` (scriptSig empty, no witness), then

```text
B = SHA256(T)
D = SHA256("PQB-v1/reveal" || round0 || round1 || p0 || p1 || p2 || B)
z = legacy SIGHASH_ALL digest of T's input, scriptCode = the vault script
```

REVIEW compares this with the vault's record:

| Record | Outcome |
| ------ | ------- |
| allocated | first disclosure |
| exposed, same `R`, script, funding, indices, picks, `B`, `D` | retry: allowed after a fresh approval |
| exposed, anything different | refused, `0x6A90` |
| retired | refused, `0x6A94` |
| not allocated, or reserved | refused, `0x6A94` |
| no history, or unknown | **emergency path**, outside custody conformance |

The device shows the network, vault number and fingerprint, each destination
and amount, the fee, what is disclosed (17 of 109 table secrets, 3 menu
signatures and the co-signature) and the binding warning. The emergency path
adds a page saying it is outside custody conformance and that a withdrawal sent
from another device or install would make this one fatal; it records the
disclosure with the vault's state left `unknown`, so later only the exact same
disclosure can be retried.

REVIEW answers only once the user decides: `0x9000` with no data on approval,
`0x6985` on rejection. The same holds for SIGN_DEPOSIT's REVIEW.

On approval the record (state, funding, indices, picks, `B`, `D`) is written to
NVM before anything leaves; the co-signature is computed by the device over
`z` with the key `d` (RFC 6979, low S, strict DER, `0x01`). A crash after the
write consumes the authorization: the host repeats the exact request.

## REVEAL_READ

`P1` = chunk, no data. Only after an approved WITHDRAW, within 60 seconds.

| Chunk | Data |
| ----- | ---- |
| `0x00` | `s[j]` for the 8 round-0 indices, in order (8 × 20) |
| `0x01` | `w[j]` for the first 5 round-1 indices (5 × 32) |
| `0x02` | `w[j]` for the last 4 round-1 indices (4 × 32) |
| `0x03` | `len (1) \|\| g[p0] \|\| len (1) \|\| g[p1] \|\| len (1) \|\| g[p2]` (menu signatures, DER `\|\| 0x01`; `len` covers both) |
| `0x04` | `len (1) \|\| co-signature (DER \|\| 0x01) \|\| Q (33)` (`len` covers DER and `0x01`) |

Chunks can be read again until chunk `0x04` is read, which ends the approval.
The host must check every preimage and menu signature against its commitment
and the co-signature against `Q`, `q` and `z`.

## MENU_POINTS

The PQB solver needs, per stage, the points `(r⁻¹·x[i])·R` for each menu scalar
`x[i]` and each recovery point `R` of the stage's `r`. They hide the scalars only
under the discrete-log assumption: keep them private to your solver.

`P1 = 0x00`, data `v (4)`: the device asks the user to authorize exporting vault
`v`'s menu points. The authorization lasts until the app exits or another vault
is authorized.

`P1 = 0x01`, data `v (4) || stage (1) || variant (1) || start (1) || count (1)`,
`count ≤ 7`, `start + count ≤ 12` for stage 0 and `≤ 16` for stages 1 and 2.
`variant` is `add_n << 1 | odd`: `R` has x-coordinate `r + n·add_n` and that
y parity. Response: `count × 33` compressed points. `0x6A80` if that `R` does
not exist (for stage 0, `r = 1`, variants 2 and 3 never do), `0x6A97` without
authorization.

`P1 = 0x02`, data `v (4) || stage (1)`, `stage < 3`: the stage's `r` (32 bytes),
which the solver needs with its points. In pqb's construction `v1` it is `1` for
stage 0 and `0x81` for stages 1 and 2; the device reports it so a host need not
assume the construction. It needs the same authorization (`0x6A97` otherwise):
the points already determine it.

Exporting points or `r` does not change any vault's state.

## State

The app keeps, per seed (wallet id), a namespace with the allocation high-water
mark `next_v`, and one record per vault, in 33 NVM slots that are each replaced
atomically (32 records, 8 seeds). Any unreadable slot makes the app refuse every
allocation and disclosure (`0x6A93`).

## Status words

| SW       | Meaning |
| -------- | ------- |
| `0x9000` | OK |
| `0x6985` | Rejected by the user |
| `0x6A80` | Invalid data: an index, pick or field out of range |
| `0x6A86` | Wrong P1/P2 |
| `0x6A87` | Wrong data length |
| `0x6A90` | Conflict: a different disclosure or funding is recorded for this vault |
| `0x6A91` | REVEAL_READ without an approved disclosure, or after it expired |
| `0x6A93` | Persistent state unreadable: allocation and disclosure refused |
| `0x6A94` | The vault's state does not allow this |
| `0x6A95` | No trustworthy history for this seed: no allocation |
| `0x6A96` | No room for another record |
| `0x6A97` | Menu points not authorized for this vault |
| `0x6D00` | Unknown instruction |
| `0x6E00` | Wrong CLA |
| `0xB001` | Command out of order |
| `0xB003` | Transaction could not be parsed |
| `0xB004` | Previous transaction does not match the outpoint |
| `0xB005` | An input does not spend the vault's deposit address |
| `0xB006` | Not this vault's locking script |
| `0xB007` | Unsupported transaction layout |
| `0xB008` | Output the device cannot show as an address |
| `0xB009` | Bad amount or non-positive fee |
| `0xB00B` | Signing failed |
| `0xB00C` | Key derivation failed |
