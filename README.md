# PQB Ledger app

A Ledger device app, in Rust, that holds the signing secrets of
[PQB](https://github.com/fireblocks-labs/pqb) (Post-Quantum Bitcoin) vaults, as
specified by the BIP draft "PQB Vault Secret Management" (profile `PQB-v1`).

A PQB vault is spent by disclosing one-time hash preimages, which a quantum
computer does not break, once. All of its secrets derive from one 32-byte vault
seed. This app derives every vault seed from the device's own seed, so the
Ledger backup is the vault backup, and it keeps the history that makes the
one-time secrets safe to disclose exactly once.

pqb's vault script (construction `v1`) also checks an ECDSA signature by a key
derived from the same seed, so the device produces that signature with each
disclosure. It is a condition of the script, not a separate feature: no
withdrawal is valid without it.

**Not audited and not submitted to Ledger.** PQB is research code that runs on
Bitcoin mainnet; treat this app the same way.

## What it does

| Operation | Command | What the device checks and shows |
| --- | --- | --- |
| **Commitments, script, root** | GET_COMMITMENTS, GET_SCRIPT, GET_VAULT | Derived on the device for any vault index. GET_VAULT can show the root's fingerprint and the vault's recorded status |
| **Create a vault** | ALLOCATE | Takes the next index (a durable high-water mark), shows "Create PQB vault #v" with its fingerprint, and records it before the script is returned |
| **Deposit address** | GET_DEPOSIT_ADDRESS | An ordinary P2WPKH address from the vault's deposit key; shown only for an allocated, never-funded vault |
| **Fund the vault** (sweep) | SIGN_DEPOSIT | Every input spends the deposit address (amounts proven by previous transactions); the one output is exactly this vault's script; one funding per vault, recorded before signatures leave |
| **Refund a deposit** | SIGN_DEPOSIT | Every input spends the deposit address; outputs are shown addresses |
| **Sign in to QSB** | SIGN_IN | A BIP-322 signature by the deposit key, so the deposit address can sign in to qsb-app; only QSB's sign-in challenge for that address, with its origin, vault, fingerprint and expiry shown; records nothing |
| **Withdraw** | WITHDRAW, REVEAL_READ | One disclosure per vault: the device builds the withdrawal `T` itself, shows destinations, amounts and fee, records the disclosure in NVM, then releases 8 + 9 table preimages, 3 menu signatures and its co-signature |
| **Solver data** | MENU_POINTS | Menu points (never scalars), after the user authorizes the export |
| **Retire** | RETIRE | Ends a vault for good |

The protocol is in [`docs/apdu.md`](docs/apdu.md).

### Derivation

```text
k = BIP 32 key at m/83696968'/39'/0'/24'/v'                     (BIP 85, BIP 39 app, 24 words)
E = HMAC-SHA512("bip-entropy-from-k", k)[0:32]
S = HMAC-SHA256(E, "pqb/vault-seed|hybrid|PQB|v1|real|main")
```

Everything else (109 table entries, 44 menu signatures, co-signing key `d`,
deposit key `dd`, commitment root `R`) follows the BIP's `PQB-v1` profile and
matches pqb's construction version `v1` (commit `82c7cba`): the pinning menu
uses `r = 1`, the round menus `r = 0x81`. The 24 words of `E` are the BIP 85 child
mnemonic a Coldcard or Jade shows for index `v`: an emergency path to pqb's own
software exists without this app. The BIP binds seeds to `main`, `testnet4` and
`regtest`; the app serves `main` only.

Allocation applies the BIP's DER screen: an index whose vault has a commitment
that parses as a strict DER signature (about 2^-33 per vault) is skipped and
never offered for funding. The commitments are the script's only 20-byte
pushes, and the item under the table is a constant; the host tests check both.

The vault script is pqb's 4,696-byte bare legacy script, whose only
seed-dependent bytes are the 154 commitments. The device embeds the script
with those slots zeroed ([`pqb-core/src/template.bin`](pqb-core/src/template.bin),
regenerated and checked against pqb by [`tools/pqb_template.py`](tools/pqb_template.py)),
so it builds and recognises a vault's exact script itself: a sweep or withdrawal
is accepted only for a script whose SHA-256 equals the one it derived.

### Disclosure lifecycle

The device keeps, per seed, an allocation high-water mark and a record per
vault (`allocated`, `exposed`, `retired`, `unknown`) in NVM, each slot replaced
atomically. Any unreadable slot makes it refuse every allocation and
disclosure.

- A disclosure is recorded before any secret or the co-signature leaves; a
  crash after recording consumes the authorization.
- After exposure, only the exact same request (indices, picks, `T`, funding)
  may be retried, after a fresh approval. A changed output, fee, sequence,
  locktime, index or pick is refused: there is no fee bump.
- Confirmation, a chain scan or a user statement never resets a vault.
- The first allocation on a seed asks whether it has ever held PQB vaults. "Used
  before" marks the seed's history unknown: no allocation, and new deposits
  need a fresh root (a new BIP 39 passphrase).
- A vault without trustworthy history (an app update, reset or another device)
  can still be withdrawn once on the **emergency path**, which the review
  labels as outside custody conformance; the record stays `unknown`. The host
  should run the BIP's restoration flow (chain check, typed attestation)
  before asking for it.

### Conformance claim and trust boundary

The app claims **derivation compatibility** (BIP 0.2.0): it passes every `main`
vector of the BIP. It does **not** claim custody conformance on its own. The
BIP makes that a claim about the whole wallet, and most of its custody rules
need a host that keeps the vault directory and can reach the chain:

| BIP custody rule | Device | Host must |
| --- | --- | --- |
| Record before release; no second witness | Disclosure recorded in NVM before anything leaves; exact retries only; no second-witness exception | Keep `T` and resend identical bytes |
| Chain check before creating a vault | None: it cannot see the chain | Check that the vault script was never paid, for every allocated index |
| Funding output confirmed and unspent before arming | Checks that the previous transaction hashes to the outpoint and pays this vault, and that the outpoint matches any recorded funding; not that it is confirmed | Check on chain before WITHDRAW |
| Vault directory: `origin.json`, `journal.jsonl`, `SPENT-DO-NOT-REUSE` | Its own NVM records instead | Keep them, written before broadcast |
| Restoration: `RESTORED-SPEND-STATE-UNKNOWN`, chain check, typed attestation, `restore-unlocked` | A seed without history gets no allocation; one withdrawal per vault on the emergency path | Run the BIP's restore flow before using the emergency path |

Neither client in this repository implements the host side yet, so a wallet
built on them is derivation-compatible only. Within one install's history the
device fails closed on its own side: it never releases a second, different
disclosure for a vault. That guarantee ends with an app update or reinstall
(Ledger erases the app's NVM), a device reset, or the same seed on another
device. The app does **not** verify the PQB
puzzle solutions: every release is a **classically bound, quantum-unverified
transaction binding**, and the review says so. The co-signature stops anyone
without a quantum computer from using the secrets for anything but the
displayed transaction; it does not stop a quantum adversary, who learns `d`
once `Q` is published.

The host is also trusted for keeping the menu points private to the solver,
and for the PQB puzzle search and witness assembly.

## Use with pqb

pqb grinds the puzzles and assembles the withdrawal; the device keeps the
secrets. [`pqb_ledger`](clients/python/) bridges the two without changing pqb:

```python
from pqb_ledger import PqbDevice, LedgercommTransport, lock_from_device, solver_stages, assemble_spend

dev = PqbDevice(LedgercommTransport())        # or SpeculosTransport(url)
lock = lock_from_device(dev, v)               # pqb's Lock, checked against the device's root
dev.authorize_menu_points(v)                  # approved on the device
stages = solver_stages(lock)                  # pqb's solver stages, menu points from the device
# ... grind with pqb, then with the plan's selection, menu picks and pin nonce:
spend = assemble_spend(lock, funding, outputs, funding_tx, selection=..., menu_pick=..., pin_nonce=...)
```

For the same grind result it builds the same spending transaction, byte for
byte, as pqb does from the seed. It checks every disclosed item against the
script's commitments, and refuses a pqb that builds construction `v1`
differently from the pinned commit.

## Layout

| Path | Contents |
| --- | --- |
| [`app/`](app/) | The device app (Ledger Rust SDK, NBGL on every device). Its `.cargo/config.toml` targets the devices, so it is its own build directory (`ledger_app.toml`). |
| [`pqb-core/`](pqb-core/) | Everything that decides what is derived, shown, signed, recorded and released, `no_std` and SDK-free so it runs in host tests: the `PQB-v1` profile, 256-bit modular arithmetic, SHA-1, the script template, streaming transaction parsing, the record store, and the deposit and withdrawal state machines. |
| [`docs/apdu.md`](docs/apdu.md) | The APDU protocol, conformance claim and status words. |
| [`tests/standalone/`](tests/standalone/) | Ragger functional tests on Speculos, with screen snapshots. |
| [`tests/application_client/pqb.py`](tests/application_client/pqb.py) | Reference implementation of `PQB-v1` the tests compare the device with. |
| [`tests/fixtures/`](tests/fixtures/) | pqb's script for the BIP's test seed. |
| [`clients/js/`](clients/js/) | TypeScript client `@pqb/ledger`: every command, verification of a disclosure against the commitments, and the BIP's portable recovery manifest. |
| [`clients/python/`](clients/python/) | `pqb_ledger`: drives the app from pqb, unmodified, so pqb's grinder and assembler work on device-held vaults. |
| [`tools/`](tools/) | Icon generator, and the template generator (needs a pqb checkout). |

## Install a release

[Releases](https://github.com/starknet-innovation/app-qsb/releases) are
pre-releases for testing. Ledger Live does not list the app, so it is
side-loaded, and the device warns that it is not genuine. Use a device you
keep for testing.

Side-loading works on Nano S+, Stax, Flex and Apex P. Nano X does not accept
side-loaded apps; its build is there for Speculos.

1. Download your device's archive and `SHA256SUMS` from the release, check the
   archive, and unpack it:

   ```bash
   shasum -a 256 -c SHA256SUMS --ignore-missing
   ```

   ```bash
   tar -xzf pqb-0.2.0-flex.tar.gz && cd pqb-0.2.0-flex
   ```

2. Install Ledger's loader (Python 3) and udev rules on Linux, as described in
   [ledgerblue](https://github.com/LedgerHQ/blue-loader-python):

   ```bash
   pip install ledgerblue
   ```

3. Connect the device, unlock it, stay on the dashboard, and quit Ledger Live.
   Then load the app:

   ```bash
   python3 -m ledgerblue.runScript --scp --fileName app-pqb.apdu --elfFile app-pqb.elf
   ```

4. Approve the install on the device. If it shows an identifier (the
   application hash), check it against `app-hash.txt` and the release notes
   first.

To remove it, use `ledgerctl delete PQB` from
[ledgerctl](https://github.com/LedgerHQ/ledgerctl).

**Reinstalling or updating the app erases its records.** Ledger clears an app's
NVM when it is replaced, so every vault of the seed loses its device history
and can then only be withdrawn on the emergency path (see
[Disclosure lifecycle](#disclosure-lifecycle)). Withdraw funded vaults before
you update.

## Build

With Docker and Ledger's builder image:

```bash
docker run --rm -v "$(pwd -P):/app" -w /app/app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest cargo ledger build nanosplus
```

Devices: `nanosplus`, `nanox`, `stax`, `flex`, `apex_p`. The binary is in
`app/target/<device>/release/app-pqb`.

## Test

Core logic on the host, against the BIP's vectors, pqb's script and solver
export, and rust-bitcoin's sighashes:

```bash
cd pqb-core && cargo test
```

Functional tests on Speculos, after building every device (or one with
`--device nanosp`), from a git checkout:

```bash
docker run --rm -v "$(pwd -P):/app" -w /app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest bash -c "pip install --break-system-packages -r tests/standalone/requirements.txt && python3 -m pytest tests/standalone --tb=short --device all"
```

The image's Python is system-managed (PEP 668), hence
`--break-system-packages`; it only touches the throwaway container. Ragger
looks for a `.git` directory to find the project root, so in a `git worktree`
(where `.git` is a file) run the tests from a copy whose `.git` is an empty
directory.

Add `--golden_run` to regenerate the screen snapshots after a UI change.

The TypeScript client's host tests; with `SPECULOS_API` set, also its tests
against Speculos running the Nano S+ build (port 5055: on macOS 5000 is AirPlay's):

```bash
cd clients/js && npm ci && npm test
```

```bash
docker run -d --rm --name pqb-speculos -p 5055:5000 -v "$(pwd -P):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest speculos --model nanosp --display headless --api-port 5000 /app/app/target/nanosplus/release/app-pqb
```

```bash
cd clients/js && SPECULOS_API=http://127.0.0.1:5055 npm test
```

The pqb adapter (installs pqb from GitHub at the pinned commit); with
`PQB_SPECULOS` set, it also checks the app's vaults against pqb's own BIP 85
derivation:

```bash
cd clients/python && pip install -e '.[dev]' && cd tests && python -m unittest -v test_device
```

```bash
cd clients/python/tests && PQB_SPECULOS=http://127.0.0.1:5055 python -m unittest -v test_device
```

To regenerate the script template from a pqb checkout that builds construction
`v1` (commit `82c7cba` or later; needs `coincurve`). It fails if the layout no
longer matches `pqb-core/src/template.rs`:

```bash
python3 tools/pqb_template.py /path/to/pqb
```

On GitHub, [`ci.yml`](.github/workflows/ci.yml) runs the device builds and
Speculos tests in the builder image on every push, and
[`host_tests.yml`](.github/workflows/host_tests.yml) the host tests.

## Open questions before a Ledger submission

- **The BIP 85 path.** The app declares `83696968'/39'/0'/24'`, the BIP 85
  BIP 39 application's key space. Ledger has to accept an app deriving there;
  ask through the intro form before investing in a submission.
- **Host custody layer.** Custody conformance needs the BIP's vault directory,
  journal, markers, chain checks and restoration flow on the host (see the
  table above). Neither client has them yet.
- **NVM continuity.** An app update erases the records and leaves only the
  emergency path. With a conforming host, its journal carries that history and
  the BIP's restoration flow covers the gap; without one, nothing does.
- **Verified transaction binding.** Checking the three puzzle solutions on the
  device would remove the "quantum-unverified" caveat; the BIP leaves that
  verifier unspecified.
- **pqb's command line.** [`clients/python/`](clients/python/) lets pqb's
  library use a device-held vault without changing pqb, but it relies on pqb
  internals and pins pqb's commit; `pqb` commands themselves don't drive the
  device.
- Registration in `LedgerHQ/ledger-app-database`, a security audit, the
  developer name (`authors` in `app/Cargo.toml`), the icons, and the rest of
  Ledger's checklist.

## License

[Apache-2.0](LICENSE). `app/build.rs` is adapted from
[LedgerHQ/app-boilerplate-rust](https://github.com/LedgerHQ/app-boilerplate-rust),
also Apache-2.0.
