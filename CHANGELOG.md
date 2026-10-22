# Changelog

## Unreleased

- HORS secrets (spec QSB-HORS-v1): derives each vault's 300 one-time secrets
  from the seed with SLIP-0021 (label `QSB-HORS`), exports their commitments and
  root, and reveals a withdrawal's 15 preimages once per vault after on-device
  approval, guarded by a 64-vault record in NVM. New APDUs `0x01`, `0x10`,
  `0x11`, `0x20`, `0x21`.
- The wallet address confirmation also shows the address type and derivation
  path. Since C SDK v27.1.3 NBGL rejects a review without such a list, which
  made every address confirmation fail.

## 0.1.0

- First version: clear-signs QSB vault deposits, withdrawal helper inputs and sign-in challenges on Nano S+, Nano X, Stax, Flex and Apex P.
