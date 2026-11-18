# pqb_ledger

Use [pqb](https://github.com/fireblocks-labs/pqb) vaults whose secrets the PQB
Ledger app holds, without changing pqb.

| Function | What it gives pqb |
| --- | --- |
| `lock_from_device(dev, v)` | A `pqb.lock.Lock` (a `DeviceLock`) for vault `v`: pqb v1's shared structure with the device's 154 commitments, checked byte for byte against the script, script hash and root the device reports. It holds no secret. |
| `solver_stages(lock)` | `pqb.grind.stages_from_lock`'s stages, with each menu stage's `r` and points from the device (after `dev.authorize_menu_points(v)`, approved on the device). |
| `assemble_spend(lock, funding, outputs, funding_tx, ...)` | `pqb.spend.Spend.assemble`, with the secrets of the device's one disclosure (approved on the device), each checked against the script's commitments; the co-signature is verified over pqb's own sighash. |

`PqbDevice` speaks the app's protocol ([`docs/apdu.md`](../../docs/apdu.md))
over `SpeculosTransport(url)` or `LedgercommTransport()` (`pip install
'.[usb]'`).

**Access to pqb.** `fireblocks-labs/pqb` is a private repository: installing
this package needs GitHub access to it (your own credentials locally; in CI, a
read-only token in the `PQB_REPO_TOKEN` secret, without which the job is
skipped).

**Pinned pqb.** The adapter uses pqb internals (`Lock._res`, `Stage` fields, the
vendored assembler's `cosig_sign`). `pyproject.toml` installs pqb at commit
`82c7cba`, and `check_pqb()` refuses any pqb whose construction `v1` script
differs from that commit's.

**Mainnet only.** The app binds every vault seed to mainnet; a `DeviceLock`
refuses to be funded anywhere else, since a disclosure on a test network would
use up that mainnet vault's one disclosure.

## Test

```bash
pip install -e '.[dev]' && cd tests && python -m unittest -v test_device
```

`tests/fake_device.py` speaks the app's protocol over pqb's own secrets for a
known seed: the tests check that a device-held vault gives the same script,
solver stages and spending transaction as the seed, and that tampered
disclosures, rejections and second disclosures are refused. With
`PQB_SPECULOS=<speculos API URL>` running the app, they also check that the
app's vaults 0 and 5 are pqb's vaults for Speculos's mnemonic.
