# exe-xray

A static, human-readable health check for Windows executables.

Point it at an `.exe` or `.dll` and get back a plain-English report: what kind of
program it is, what APIs it can reach for, which strings it carries around,
whether it is packed, whether its signature still covers the file, and one
sentence that says *this thing is probably a keylogger with an autostart*.

The target is **never** executed, loaded, mapped or emulated — the tool only
reads the file bytes. Pure Python standard library, no dependencies, no network.

```
$ python xray.py C:\Windows\System32\notepad.exe
```

## Why

`dumpbin`, `pe-bear`, `pefile` and friends show you *fields*. This shows you
*meaning*: it maps the import table onto capabilities (network, injection,
keyboard capture, persistence, anti-debug...), scores them, and writes a verdict
a human can read without knowing what `SetWindowsHookExW` does.

## Install

Nothing to install. Python 3.9+:

```
python xray.py <file>            # run from the checkout
python -m exe_xray <file>        # same thing
pip install .                    # optional: gives you an `exe-xray` command
```

## Usage

```
exe-xray FILE [FILE ...] [options]

  --json                 full structured report instead of prose
  --compact              one summary line per file
  --min-string-len N     shortest literal to keep (default 4)
  --max-strings N        samples kept per string category (default 4000)
  --no-strings           skip literal extraction: big win on string-dense files,
                         but on a huge image the checksum pass below is usually
                         the larger cost
  --no-checksum          skip the PE checksum verification, the most expensive
                         pass over the file; the report then says the checksum
                         was *not verified* instead of inventing a verdict
  --max-file-mb MB       refuse files above this size (default 512)
  --color {auto,always,never}
  --version
```

Exit codes: `0` report produced, `1` the file could not be analysed (with the
reason on stderr), `2` bad arguments.

### Big files

Checksum verification is the most expensive pass over the file (section
statistics, imports and strings are all bounded). On the 220 MiB `MRT.exe` the
checksum alone used to take 166 s of a 232 s run. It is now a batch sum (see
`exe_xray/pe.py`) that finishes in ~8 s, and `--no-checksum` removes even that
when you only want the imports/strings/verdict.

```
$ python xray.py C:\Windows\System32\MRT.exe --no-checksum --compact
```

## What it reports

| Section | Content |
| --- | --- |
| **FILE** | size, mtime, SHA-256 / SHA-1 / MD5 |
| **HEADERS** | PE32 vs PE32+, machine, subsystem, linker version, compile timestamp, entry point, image base, DllCharacteristics (ASLR/NX/CFG), checksum validity, .NET/CLR header, PDB path, MSVC Rich-header build numbers |
| **SIGNATURE** | embedded Authenticode: PKCS#7 parsing, signer DN, issuer, validity window, timestamp presence, and **re-verification of the file digest the signature commits to** |
| **SECTIONS** | per-section size, entropy, R/W/X flags, overlay size |
| **IMPORTS** | every DLL and API, bucketed into capabilities |
| **STRINGS** | ASCII + UTF-16LE literals bucketed into URLs, IPs, domains, registry paths, file paths, User-Agents, credential-shaped strings, SQL, base64 blobs, wallet addresses, exfil endpoints, offensive-tooling markers |
| **PACKING** | section-name signatures (UPX/VMProtect/Themida/ASPack/MPRESS/...), entropy, W+X sections, VirtualSize≫RawSize, tiny import table, overlay ratio — with a score |
| **VERDICT** | one sentence + ranked signals + 0–100 risk score |

### Capability buckets

`network`, `http`, `download`, `dns`, `netauth`, `netinfo`, `file`, `registry`,
`process`, `thread`, `injection`, `service`, `driver`, `crypto`, `dpapi`,
`keyboard`, `hook`, `screen`, `input`, `clipboard`, `privilege`, `shell-exec`,
`anti-debug`, `timing`, `enum`, `shadowcopy`, `wifi`, `audio`, `netapi`, `com`,
`ui`, `console`, `crt`, `runtime`.

The mapping lives in `exe_xray/capabilities.py` as a plain table
(`module -> [(api pattern, bucket)]`) and is meant to be extended. `api-ms-win-*`
API sets are mapped back onto their real modules.

Risk scoring is built on one rule: **the import table may not decide the verdict
on its own.** Imports say what a binary can reach for, never what it does, so
the category score is capped at 45/100 no matter how many buckets a large program
touches. On top of that cap:

| Evidence | Effect |
|---|---|
| Capability breadth (capped) | 0–45 |
| Authenticode signature verifies against its signer certificate | −35 |
| Ships in System32/SysWOW64/WinSxS with a Microsoft `CompanyName` | −20 |
| Embedded signature present but not matching the file | +20, never below `medium` |
| Packed / protected image | +35 |
| Hard-coded exfil endpoint, keylogging plus sockets, offensive tooling markers | +8 … +15 each |

So a browser with sockets and files stays `minimal`, while five lines of code
that hook the keyboard and phone home goes `high`. A file whose signature was
broken — altered after signing, or forged — can never be reported as `minimal`,
because "we could not validate this" must not read as "this looks clean".

Signature credits are only applied when the signature actually verifies: the tool
performs RSA PKCS#1 v1.5 verification against the signer certificate, so a
rewritten `messageDigest` in the certificate table does not buy a file a discount.

## Example

A real file that exists on every Windows box (output trimmed):

```
$ python xray.py C:\Windows\System32\notepad.exe --color never
exe-xray 0.1.0  ·  static PE inspection  ·  the target is never executed

FILE
  path      C:\Windows\System32\notepad.exe
  size      352 KiB (360,448 bytes)
  modified  2026-09-10 05:47:09Z
  sha256    468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e
  md5       8a1d8175ccca97054cdb25acbb4cc07e

HEADERS
  format    PE32+  x64 (AMD64)  EXE  subsystem=windows-gui  linker 14.38
  compiled  1979-02-19 18:32:04Z  (before 1980: not a plausible build time)
  entry     0x19c0   image base 0x140000000   image size 360 KiB
  flags     HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, GUARD_CF, TERMINAL_SERVER_AWARE
  checksum  valid
  .NET      no (native image)
  PDB       notepad.pdb
  toolchain MSVC Rich header, build(s) 264, 261, 260, 259, 258

SIGNATURE
  status    unsigned  no IMAGE_DIRECTORY_ENTRY_SECURITY entry: no embedded signature (Windows may still trust the file through a system catalog)

SECTIONS
  name            virt       raw  entropy  flags
  .text        157,666   159,744      6.24  CODE X R
  fothk          4,096     4,096      0.02  CODE X R
  .rdata        42,696    45,056      5.58  IDATA R
  .data         10,048     4,096      1.62  IDATA R W
  .pdata         4,632     8,192      3.32  IDATA R
  .didat           248     4,096      0.25  IDATA R W
  .rsrc        123,344   126,976      6.97  IDATA R
  .reloc           860     4,096      1.62  IDATA DISCARDABLE R

VERSION INFO
  CompanyName        Microsoft Corporation
  FileDescription    Notepad
  FileVersion        10.0.26100.9278 (WinBuild.160101.0800)
  OriginalFilename   NOTEPAD.EXE
  ProductName        Microsoft® Windows® Operating System
  manifest requests: asInvoker

IMPORTS  56 DLLs, 315 functions, 224 resolved to generic runtime glue, 20 outside the table
  anti-debug     2x  api-ms-win-core-debug-l1-1-0.dll:IsDebuggerPresent, api-ms-win-core-debug-l1-1-0.dll:OutputDebugStringW
  process        2x  api-ms-win-core-processthreads-l1-1-0.dll:CreateProcessW, ...
  clipboard      1x  user32.dll:OpenClipboard
  file           9x  api-ms-win-core-file-l1-1-0.dll:DeleteFileW, ..., CreateFileW, ReadFile, ...

STRINGS  3,608 extracted, 2,379 unique
  URLs / endpoints (3)
    http://schemas.microsoft.com/SMI/2016/WindowsSettings
    https://go.microsoft.com/fwlink/?LinkId=834783
    https://go.microsoft.com/fwlink/p/?linkid=838060

PACKING  no packing indicators (score 0/100)
  - no packer signatures, normal entropy, healthy import table

VERDICT
  Most likely a 64-bit GUI application. From the import table: drives a window message
  loop, reads and writes files, can start or open other processes. Risk: minimal (0/100).
```

### Synthetic fixtures

Two more examples use the test fixtures. They are **not** in the repository:
`tests/fixtures/` is git-ignored and the files are generated on the spot by the
test run, so after a fresh clone this works, and nothing else does:

```
$ python -m unittest discover -s tests      # writes tests/fixtures/*.exe
$ python xray.py tests\fixtures\suspicious.exe
```

```
IMPORTS  4 DLLs, 18 functions, 0 resolved to generic runtime glue, 0 outside the table
  injection      3x  kernel32.dll:CreateRemoteThread, kernel32.dll:WriteProcessMemory, kernel32.dll:VirtualAllocEx
  keyboard       1x  user32.dll:GetAsyncKeyState
  hook           1x  user32.dll:SetWindowsHookExA
  service        2x  advapi32.dll:CreateServiceW, advapi32.dll:OpenSCManagerA
  anti-debug     1x  kernel32.dll:IsDebuggerPresent
  network        6x  ws2_32.dll:WSAStartup, ws2_32.dll:socket, ws2_32.dll:connect, ...
  process        2x  kernel32.dll:OpenProcess, kernel32.dll:CreateProcessW
  registry       1x  advapi32.dll:RegSetValueExW

STRINGS  31 extracted, 31 unique
  URLs / endpoints (2)
    http://c2.example.invalid/gate.php?id=%s
    https://discord.com/api/webhooks/1234567890/abcdefg
  registry paths (1)
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  exfiltration endpoints (1)
    https://discord.com/api/webhooks/1234567890/abcdefg

VERDICT
  Most likely a 32-bit GUI application. From the import table: drives a window message
  loop, talks to the network, touches the registry, can start or open other processes,
  can write into another process, hooks input. Worth a look: can write/inject code into
  another process (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx); reads key
  state and also opens sockets: a keylogger with an exfil path; hard-coded exfiltration
  endpoint: https://discord.com/api/webhooks/1234567890/abcdefg. Risk: high (100/100).
  - HIGH           can write/inject code into another process (CreateRemoteThread, ...)
  - HIGH           reads key state and also opens sockets: a keylogger with an exfil path
  - HIGH           hard-coded exfiltration endpoint: https://discord.com/api/webhooks/...
  - WARN           installs Windows hooks (classic in-process injection vector)
  - WARN           autostart registry path referenced: HKEY_CURRENT_USER\...\Run
  - NOTE           checks for debuggers/analysis (IsDebuggerPresent)
```

A fixture aimed at the packer heuristic (same warning as the test suite: the
fixture names its sections `UPX0`/`UPX1`, i.e. it *tells* the detector the
answer; it exercises the section-name table, not real packer output):

```
$ python xray.py tests\fixtures\packed.exe
PACKING  likely packed / protected (score 100/100)
  - section name 'UPX0' is the signature of UPX
  - section name 'UPX1' is the signature of UPX
  - section UPX0 is both writable and executable
  - section UPX1 has entropy 7.78 (>7.2 is typical for compressed or encrypted code)
```

A real signed binary, same tool:

```
$ python xray.py "C:\Program Files\Python312\python.exe"
```

```
SIGNATURE
  status    valid  SHA256 file digest matches the signed digest
  signer    CN=Python Software Foundation, O=Python Software Foundation, ...
            issuer CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, ...
  timestamped by an RFC3161/countersignature authority
```

Packed sample:

```
$ python xray.py tests\fixtures\packed.exe
PACKING  likely packed / protected (score 100/100)
  - section name 'UPX0' is the signature of UPX
  - section name 'UPX1' is the signature of UPX
  - section UPX0 is both writable and executable
  - section UPX1 has entropy 7.78 (>7.2 is typical for compressed or encrypted code)
```

### JSON

```
$ python xray.py app.exe --json --no-strings
{
  "tool": {"name": "exe-xray", "version": "0.1.0"},
  "file": {"path": "...", "size": 818512, "sha256": "...", "md5": "..."},
  "pe": {"format": "PE32+", "machine": "x64 (AMD64)", "subsystem": "windows-console",
         "checksum": {"stored": "0x...", "computed": "0x...", "valid": true},
         "sections": [{"name": ".text", "entropy": 6.37, "flags": ["CODE", "X", "R"]}]},
  "signature": {"present": true, "status": "valid",
                "signers": [{"subject": "CN=...", "issuer": "CN=...", "timestamped": true}]},
  "imports": {"dll_count": 42, "function_count": 237,
              "categories": {"network": {"weight": 5, "apis": [...]}}},
  "strings": {"total": 13526, "by_category": {"url": {"samples": [...]}}},
  "packing": {"score": 0, "verdict": "no packing indicators", "reasons": []},
  "risk": {"score": 12, "level": "low", "signals": [{"id": "embedded-urls", ...}]},
  "verdict": {"kind": "64-bit console application", "summary": "Most likely a ..."}
}
```

## Code layout

```
xray.py                  thin launcher
exe_xray/pe.py           dependency-free PE/COFF parser (headers, sections, imports,
                         exports, resources + VS_VERSIONINFO, debug/PDB, Rich header,
                         CLR header, overlay, checksum)
exe_xray/der.py          small ASN.1 reader
exe_xray/authenticode.py PKCS#7 SignedData walk + Authenticode file digest check
exe_xray/strings.py      literal extraction + classification
exe_xray/capabilities.py import table -> capability table
exe_xray/analyze.py      pipeline, packing heuristics, risk scoring, verdict
exe_xray/report.py       human / JSON / compact rendering
tests/make_fixtures.py   builds synthetic PE fixtures (no compiler involved)
tests/test_xray.py       unittest suite
```

## Tests

```
python -m unittest discover -s tests -v
```

The suite generates its own inputs: `setUpModule` calls `tests/make_fixtures.py`
and writes `tests/fixtures/*.exe` on the spot (no compiler, no network, nothing
executed). That directory is listed in `.gitignore` — the fixtures are build
products, not checked-in samples, so a fresh clone has no `tests/fixtures/` until
the test command above has run once. `python tests/make_fixtures.py` does the
same without running the tests.

32 tests cover header parsing, import classification, string buckets, packing,
risk scoring, error handling, both renderers, the CLI exit codes, the batch
checksum against the old byte-loop oracle, the `--no-checksum` report marker,
and — when the files exist on the machine — real `notepad.exe` and a signed
`python.exe`.

Three notes about deliberate test design:

* The UPX fixture names its sections `UPX0`/`UPX1`, so it can only prove that the
  section-name table still fires. The test says so in its docstring, and a
  negative control (high-entropy sections with neutral names) covers the part
  that would otherwise go untested.
* The three Authenticode negative controls (truncated certificate table, modified
  section without digest repair, empty certificate table) need a genuine
  embedded signature, so they skip — visibly — when the host has no signed
  binary or the verifier is mid-rewrite. A skip there means "not proven".
* Nothing is skipped to hide an unexpected answer: the signed-`python.exe` test
  asserts the status against the closed set `{valid, unsigned}` and tallies which
  case the host produced.

## Limitations

Honest list:

- **Static only.** Packed or virtualised binaries hide most of their imports and
  strings; the report says so, but it cannot see what runs after unpacking.
- **Signature integrity, not trust.** The file digest is re-verified against the
  embedded PKCS#7 signature. Certificate chain, revocation and timestamp
  authority are *not* validated (that needs CryptoAPI/WinVerifyTrust).
- **Catalog signatures are invisible.** Most Windows system binaries are trusted
  through a catalog `.cat` file, not an embedded signature; Windows may report
  "Valid" while this tool reports "no embedded signature". Both are true.
- **Import-based reasoning has blind spots.** APIs resolved at runtime
  (`GetProcAddress` on a hash, syscalls) leave no trace in the import table.
- **No emulation, no decompilation, no deobfuscation.** This is a triage
  instrument, not a verdict.
- Risk scores are a heuristic built for ranking files against each other, not a
  probability that something is malware.

## License

MIT — see [LICENSE](LICENSE).
