# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public surface — the report sections, the JSON
shape, the risk-score arithmetic and the exit codes — may still change between
minor versions. Anything that changes a documented field or an exit code is
listed here as `Changed`, never slipped in silently.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-11-07

First public release. `exe-xray` reads a PE file and writes a report a human can
act on, without ever executing, loading, mapping or emulating the target.

### Added

- **Static PE inspection pipeline** — dependency-free PE/COFF parser covering
  headers (PE32/PE32+, machine, subsystem, linker version, compile timestamp,
  entry point, image base, `DllCharacteristics`, CLR/.NET header, debug/PDB path,
  MSVC Rich header), sections (size, entropy, R/W/X flags, overlay) and the PE
  checksum, verified with a batched sum instead of a byte-by-byte loop.
- **Authenticode reader** — PKCS#7 `SignedData` walk plus a small ASN.1/DER
  reader: signer and issuer DN, validity window, timestamp presence, and
  re-verification of the file digest the signature actually commits to
  (RSA PKCS#1 v1.5 against the signer certificate).
- **Capability classification** — the import table is mapped onto 34 buckets
  (`network`, `injection`, `keyboard`, `hook`, `service`, `driver`, `dpapi`,
  `shadowcopy`, `anti-debug`, …), with `api-ms-win-*` API sets folded back onto
  their real modules, and a mapping table meant to be extended.
- **String classification** — ASCII and UTF-16LE literals bucketed into URLs,
  IPs, domains, registry paths, file paths, User-Agents, credential-shaped
  strings, SQL, base64 blobs, wallet addresses, exfiltration endpoints and
  offensive-tooling markers.
- **Packing heuristics with a three-layer evidence model** — identity (packer
  section names and magic: UPX, VMProtect, Themida, ASPack, MPRESS, …),
  structure (uninitialised W+X unpack destination, resolver-only import table,
  non-printable section names) and corroboration (executable entropy, entry point
  placement, RWX sections, overlay, import count). Corroboration alone can never
  call a file packed.
- **Risk scoring with an import-table cap** — capability breadth is capped at
  45/100, so imports can never decide a verdict on their own; combination signals,
  structural evidence and positive credits (verified signature, Windows component)
  are applied on top. Levels: `minimal` / `low` / `medium` / `high`.
- **Batch mode** (`--batch`) — recursive directory walk, glob expansion or a
  single file; risk-sorted table, `--csv`, `--json`, `--max-files`,
  `--min-risk-level`, and the `--fail-on-risk N` CI gate. Exit codes are part of
  the interface: `0` ok, `1` nothing analysed or gate tripped, `2` bad arguments,
  `130` interrupted with partial results printed.
- **Four output renderers** — prose report, `--compact` one-liner, JSON, and the
  batch table/CSV, plus ANSI colour that can be forced off for logs.
- **Test suite and synthetic fixtures** — `tests/make_fixtures.py` builds PE
  fixtures from scratch (no compiler, no network, nothing executed);
  `setUpModule` regenerates them, and `tests/fixtures/` stays out of the repo.
- **CI matrix** — the suite on Ubuntu and Windows across Python 3.9–3.13, plus
  CLI smoke tests, a `pip install .` entry-point check and a guard that fails the
  build if a third-party import creeps in.
- **Docs** — English README and a Simplified Chinese translation
  (`README.zh-CN.md`), with the packing investigation written up in
  `NOTES-packing.md`.
- **Repo hygiene** — credential-shaped files are git-ignored and never committed.

### Changed

- Packing evidence was rebuilt around measured weights: a large share of the
  stock Windows images the old rules flagged were resource-only DLLs, kernel
  loaders or bottom-layer libraries, so "no import table", "high entropy" and
  "entry point not in the first section" were demoted to corroborating signals
  and each carries a written justification for its weight.
- Exfiltration-endpoint and offensive-tooling detection were tightened, so a
  policy DLL carrying the literal `lsass.exe` is reported as a finding for the
  analyst to judge rather than being scored as behaviour.
- One credit per packer family instead of one per section: `UPX0` + `UPX1` are a
  single observation seen twice, and summing them let a two-section stub score
  80 points on its own.
- The DLL export-count discount was removed from the arithmetic; the caveat now
  lives in the report, where a reader can weigh it, instead of in a magic factor
  that compared unrelated images.
- Signature credits are only applied when the signature genuinely verifies, so a
  rewritten `messageDigest` in the certificate table buys no discount — and a
  signature that is present but does not match is now positive evidence of
  tampering (`+20`, never below `medium`).
- Line endings are normalised to LF through `.gitattributes` so checkouts on
  Windows and Linux agree byte-for-byte.
- README gained a CI status badge and the batch-mode section.

### Fixed

- `test_packing` now generates the fixtures it reads, so the packing tests run
  from a fresh clone instead of skipping on missing files.
- Real-binary test specimens are selected by `MZ` magic rather than by platform,
  so a Windows-hosted run no longer assumes anything about the OS it sits on.
- Checksum verification no longer dominates a large-file run: the batched sum
  took a 220 MiB image from 166 s to roughly 8 s, and `--no-checksum` reports
  "not verified" rather than inventing a verdict.
- An unreadable directory is a problem, not a crash: it lands on stderr and in
  the footer count, and the sweep keeps going. A single unparseable file never
  ends a batch run either.

[Unreleased]: https://github.com/wc985732-lang/exe-xray/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wc985732-lang/exe-xray/releases/tag/v0.1.0
