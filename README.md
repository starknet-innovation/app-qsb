# QSB Ledger app

A Ledger device app, in Rust, for
[QSB](https://github.com/starknet-innovation/qsb-app) quantum-safe Bitcoin
vaults. It does two jobs:

- **Clear-signs the wallet side**: the deposit into a vault, the helper input
  of a withdrawal from a vault, and the QSB service's sign-in challenge. It
  signs nothing else.
- **Holds the vaults' HORS secrets** (spec QSB-HORS-v1): derives each vault's
  300 one-time secrets from the seed, exports only their commitments, and
  reveals the 15 a withdrawal needs once per vault, after you approve.

**Not audited and not submitted to Ledger.** QSB itself is a research
snapshot that runs on Bitcoin mainnet; treat this app the same way.

## What it signs

QSB's wallet is one P2WPKH or nested SegWit (P2SH-P2WPKH) address, used for
sign-in, deposits and the withdrawal's helper input (qsb-app
`docs/KEY-CUSTODY.md`). The app holds that key: BIP-84 `m/84'/0'/account'/change/index`
or BIP-49 `m/49'/0'/…` on mainnet, with the standard limits (account ≤ 100',
index ≤ 50,000). The vault input's HORS authorization is separate: see
[HORS secrets](#hors-secrets) for vaults whose secrets the device holds.

| Operation | What the device checks | What it shows |
| --- | --- | --- |
| **Deposit** (`fundingPsbt`) | 1–8 inputs, each spending the wallet's address, each amount proven by its full previous transaction; output 0 is a QSB vault script; an optional output 1 returns change to the wallet; positive fee | Amount, vault fingerprint, fees (and a warning above 10%) |
| **Withdrawal** (`helperPsbt`) | Input 0 spends the wallet's address; input 1 spends a QSB vault output, proven by the deposit transaction; one output to a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address; positive fee. Signs input 0 only, SIGHASH_ALL | Vault fingerprint, amount, destination address, fees (and a warning above 10%) |
| **Sign-in** (BIP-322) | The exact challenge template from qsb-app's `server/app.ts`, for `bitcoin-mainnet`, naming the signing address | Origin, address, expiry |

**Vault recognition.** A QSB Config A vault script is always 9,923 bytes;
everything but its 300 HORS commitments (20 bytes each) is the same in every
vault. The device streams the script, hashes the 3,923 fixed bytes and compares
that with a constant, so any other script is refused. The vault is shown by its
script fingerprint, SHA-256 of the script: qsb-app's `scriptHash`, shown as
"Script fingerprint" in its restore screen, and the script hash block
explorers index. The check is in [`qsb-core/src/vault.rs`](qsb-core/src/vault.rs).

**Amounts and fees.** Every input's previous transaction is streamed and hashed
to its txid, so input amounts are proven rather than claimed. The withdrawal's
fee depends on the vault amount, which the helper's BIP-143 signature does not
cover, so it is read from the deposit transaction, about 10 kB with the vault
script, without buffering it.

Nothing is shown that the device didn't derive itself from the bytes it signs.
Signatures are RFC 6979 ECDSA, normalised to low S.

### What the device does not protect

- **Whose vault it is.** The template check proves a script is a QSB vault,
  not that it is yours: a malicious host can pay into a vault whose HORS
  secrets only it knows. Compare the fingerprint on the device with the one
  in your own backup (qsb-app's restore screen) before approving a deposit.
- **The vault's funds.** A QSB vault script has no wallet key in it: spending
  it takes the HORS preimages and a GPU search. Approving a withdrawal's
  signature guarantees only that the helper input this device signs goes to
  the destination and fee shown; it can't stop someone holding the preimages
  from spending the vault with another helper. For vaults whose secrets the
  QSB client holds, that is the client; for vaults derived on this device, the
  reveal is the point to check (see [HORS secrets](#hors-secrets) for its v1
  limits). qsb-app's `docs/KEY-CUSTODY.md` describes the same trust model.
- **Timing fields.** Version, locktime and sequences are signed but not
  shown. A far-future locktime can delay a transaction; it can't redirect
  funds.

## HORS secrets

A QSB vault's script commits to 2 × 150 one-time HORS secrets; a withdrawal
reveals 15 of them. Today the QSB client draws them with `os.urandom` and
keeps them in an encrypted backup file. With this app they come from the
Ledger instead:

```text
K          = SLIP-0021 key for the label "QSB-HORS"   (no secp256k1 key involved)
s[v][r][i] = HMAC-SHA256(K, "QSB-HORS-v1" ‖ 0x00 ‖ net ‖ v ‖ r ‖ i)[0..20)
c[v][r][i] = RIPEMD160(SHA256(s))                    (the commitments qsb-app uses today)
```

- **A new vault is a new index `v`.** The host picks the next unused one and
  reads its 300 commitments (13 GET_COMMITMENTS per round) and their root;
  the vault script is built from them unchanged. GET_COMMITMENT_ROOT can show
  the root's fingerprint ("9b25 7b6a cd00 017b") to compare with the QSB app.
- **Nothing secret is stored or exported.** Secrets are re-derived per
  command; the device keeps only the reveal record below. Commitments are
  public. A vault can be rebuilt from the seed and `v`: no backup file holds
  secrets any more.
- **One reveal per vault.** REVEAL_PREPARE shows the vault, network, amount,
  destination and "15 of 300"; on approval ("Hold to reveal", or "Reveal" on
  Nano) the device records the reveal in NVM before REVEAL_READ hands out the
  15 preimages. The same reveal again is allowed (a retry); a different one for
  the same vault is refused. The record holds 64 vaults, keyed per wallet so a
  BIP-39 passphrase's vaults don't collide with the main seed's; when full, the
  device asks to forget the oldest. An approval lapses after 60 seconds. The
  fingerprint check warns not to fund a vault whose secrets were revealed.

What this does **not** do yet (the spec's v1 scope):

- **The amount and destination on the reveal screen are the host's word.**
  The device can't yet check that the 15 indices belong to that withdrawal: a
  lying host can get one reveal for a withdrawal of its choosing. The screen
  says "host-reported, not verified". The spec's phase 2 closes this by
  recomputing QSB's digest puzzle on the device.
- **The record is per device and per install.** Another device with the same
  seed, a reset, or an app update or reinstall (NVM in `.nvm_data` is erased)
  starts empty. The QSB service's duplicate-root and submission checks are the
  second line.
- **The seed becomes the vault's single point of failure:** whoever holds it
  can derive every vault's secrets and spend outside the service.

The protocol is in [`docs/apdu.md`](docs/apdu.md#hors-secrets);
[`tests/application_client/hors.py`](tests/application_client/hors.py) is a
reference implementation, checked against SLIP-0021's published vectors.

## Layout

| Path | Contents |
| --- | --- |
| [`app/`](app/) | The device app (Ledger Rust SDK, NBGL on every device). Its `.cargo/config.toml` targets the devices, so it is its own build directory (`ledger_app.toml`). |
| [`qsb-core/`](qsb-core/) | Everything that decides what is shown, signed and revealed, `no_std` and SDK-free so it runs in host tests: streaming transaction parser, vault matcher, BIP-143/BIP-322 digests, address encoding, sign-in parser, the signing state machine, HORS derivation and the reveal guard. |
| [`docs/apdu.md`](docs/apdu.md) | The APDU protocol and status words. |
| [`tests/standalone/`](tests/standalone/) | Ragger functional tests on Speculos, with screen snapshots. |
| [`tests/fixtures/`](tests/fixtures/) | qsb-app's first mainnet deposit and withdrawal, and generated vault scripts. |
| [`clients/js/`](clients/js/) | TypeScript client, `LedgerQsbSigner` (a Signer for the QSB SDK) and `QsbHors` (commitments, verified against the root, and reveals, verified against the commitments). |
| [`tools/make_icons.py`](tools/make_icons.py) | Generates the icons and glyphs. |

## Build

With Docker and Ledger's builder image (multi-arch, so it runs natively on Apple Silicon):

```bash
docker run --rm -v "$(pwd -P):/app" -w /app/app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest cargo ledger build nanosplus
```

Devices: `nanosplus`, `nanox`, `stax`, `flex`, `apex_p`. The binary is in
`app/target/<device>/release/app-qsb`.

## Test

Core logic, on the host. These include qsb-app's first mainnet deposit and
withdrawal: the app's digests verify the signatures already on chain.

```bash
cd qsb-core && cargo test
```

Functional tests on Speculos, after building every device (all devices, or
one with `--device nanosp`). Ragger finds the project root by its `.git`
directory, so run them from a git checkout:

```bash
docker run --rm -v "$(pwd -P):/app" -w /app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest bash -c "pip install -r tests/standalone/requirements.txt && pytest tests/standalone --tb=short --device all"
```

Add `--golden_run` to regenerate the screen snapshots after a UI change.

The TypeScript client's host tests, then its end-to-end tests against Speculos
running the Nano S+ build. On macOS port 5000 belongs to AirPlay, hence 5055:

```bash
cd clients/js && npm ci && npm test
```

```bash
docker run -d --rm --name qsb-speculos -p 5055:5000 -v "$(pwd -P):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest speculos --model nanosp --display headless --api-port 5000 /app/app/target/nanosplus/release/app-qsb
```

```bash
cd clients/js && SPECULOS_API=http://127.0.0.1:5055 npm test
```

Ledger's guidelines enforcer (`/opt/enforcer.sh` in the image) reads the repo
name from the `origin` remote, so add one before running it. Its
`app_load_params` check fails until the app is registered in
`LedgerHQ/ledger-app-database`.

## Use with the QSB SDK

`LedgerQsbSigner` has the shape of the SDK's `Signer` (`sdk/signer.ts`):

```ts
import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import { LedgerQsbSigner } from "@qsb/ledger";

const transport = await TransportNodeHid.create();
const signer = await LedgerQsbSigner.connect(transport, "m/84'/0'/0'/0/0", { verifyAddress: true });
const client = new QsbClient({ signer, /* … */ });
```

The SDK calls `signMessage` for sign-in and `signPsbt(address, psbt, [0])` for
the withdrawal helper; deposits are signed with `signPsbt(address, psbt, every
input)`. Signatures come back as PSBT partial signatures. The `qsb` CLI has no
Ledger signer option yet; its `external` signer mode works with this client.

## Open questions before a Ledger submission

- **Which route Ledger accepts.** Ledger's docs send Bitcoin layer-2 apps to the
  C [`app-btcext-boilerplate`](https://github.com/LedgerHQ/app-btcext-boilerplate)
  on top of the Bitcoin app, while requiring Rust for new apps. This app
  declares `84'/0'` and `49'/0'`, Bitcoin's own key space. Ask Ledger through
  the intro form before investing in a submission.
- Registration in `LedgerHQ/ledger-app-database`, a security audit, the
  developer name (`authors` in `app/Cargo.toml` is a placeholder), the icons,
  and the other deliverables in Ledger's checklist.
- The vault template is tied to qsb-app's Config A generator (commit
  `2c917205…`). A new QSB script version needs a new skeleton hash.
- **SLIP-21 on hardware.** Speculos and the Ledger Bitcoin app agree that the
  OS returns SLIP-0021's key in the first 32 bytes of its output, and Speculos
  matches the published vectors; confirm once on a real device with a test
  seed before any vault holds funds.
- **Ledger's tooling and the SLIP-21 label.** The guidelines enforcer doesn't
  read `path_slip21` from a Rust app's metadata, so its `app_load_params` check
  can't pass for the `QSB-HORS` label without a change to
  `LedgerHQ/ledger-app-workflows`.
- **qsb-app integration** (the spec's "Host integration"): a `ledger-slip21-v1`
  vault source, a bridge entry point that builds the script from commitments,
  `bridge.assemble` taking the 15 preimages, and the service-side duplicate-root
  and reveal-set checks.
