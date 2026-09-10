#!/usr/bin/env python3
# =============================================================================
# sslspray.py
#
# AUTHORIZED INTERNAL SECURITY ASSESSMENT TOOL
# Scope: TLS/SSL protocol-version discovery on internal web servers. Same
#        two-phase masscan + worker-pool architecture as ssh_vuln_scan.py /
#        quantum_readiness_spray.py, applied to protocol-downgrade scope
#        (SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3).
#
# -----------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES
# -----------------------------------------------------------------------------
# Phase 1 (Discovery): Uses masscan to rapidly identify hosts on the
#   configured internal subnets with a web/TLS port open (see TLS_PORTS
#   below). Same rationale as the sibling scripts: the configured scope
#   includes a /8, and pointing nmap's own host discovery at that much
#   address space would dominate the whole run.
#
# Phase 2 (Assessment): For every host discovered in Phase 1, runs nmap
#   -Pn -n (skip nmap's own host discovery and DNS -- both already done)
#   with the ssl-enum-ciphers / sslv2 / ssl-cert NSE scripts against that
#   host's open TLS port(s) in a single nmap process, in a worker pool of
#   concurrent nmap processes (same shape as ssh_vuln_scan.py's Phase 2,
#   just one nmap invocation may cover more than one port per host here).
#   Each port's supported-protocol booleans, least-cipher-strength grade,
#   individual weak (C/D/F-graded) cipher suites, and certificate details
#   (subject/issuer, self-signed, key, signature algorithm, expiry) are
#   extracted from nmap's XML output. ssl-cert rides the same TLS
#   connection ssl-enum-ciphers already opens, so it costs no extra
#   handshake.
#
# -----------------------------------------------------------------------------
# WHY NMAP+NSE INSTEAD OF sslscan / sslyze / testssl / openssl s_client
# -----------------------------------------------------------------------------
# All of those are available on the Kali box this runs on and were
# considered. nmap's `ssl-enum-ciphers` (SSLv3 through TLS 1.3) plus
# `sslv2` (SSLv2) was chosen because it is the only combination that:
#   - covers the full SSLv2-through-TLS1.3 range in one engine, so there
#     is exactly one XML output format to parse (matching the sibling
#     scripts' "single engine, single parser" shape) instead of stitching
#     together sslscan's XML, sslyze's JSON, and openssl s_client's
#     free-text output;
#   - runs unattended per-host inside the same worker-pool model already
#     proven out in ssh_vuln_scan.py, with no extra parsing code path.
# sslscan/sslyze remain useful for a manual deep-dive on a single host
# this script flags -- deliberately out of scope for the bulk sweep.
#
# -----------------------------------------------------------------------------
# NON-DESTRUCTIVE / SAFETY GUARANTEES
# -----------------------------------------------------------------------------
# No authentication is ever attempted and no application-layer requests are
# sent. The NSE scripts used here (ssl-enum-ciphers, sslv2, ssl-cert) only
# perform TLS/SSL handshakes -- offering and recording which protocol
# versions and cipher suites the server accepts, and reading the certificate
# the server presents during that same handshake -- then close the
# connection. No exploitation of any downgrade attack (e.g. POODLE, BEAST)
# is attempted; this tool only enumerates what the server offers.
#
# THIS TOOL MUST ONLY BE RUN AGAINST NETWORKS YOU ARE EXPLICITLY AUTHORIZED
# TO ASSESS. Confirm written authorization / an active engagement scope
# before running this script.
#
# -----------------------------------------------------------------------------
# LIMITATIONS AND ASSUMPTIONS
# -----------------------------------------------------------------------------
#   - Requires `masscan` on PATH (unless --skip-masscan with a valid
#     --masscan-output-file) and `nmap` on PATH (always -- there is no
#     fallback protocol-enumeration path here, same decision as
#     ssh_vuln_scan.py made for nmap+NSE over ssh-audit).
#   - `openpyxl` is only needed for the .xlsx step; its absence degrades to
#     CSV-only rather than failing the run.
#   - A masscan hit only proves the port is open, not that TLS is what's
#     listening there -- see the script-seen guard in parse_port() below.
#   - Reverse DNS depends on corporate DNS infrastructure; failures resolve
#     to "" (blank) and do not stop the scan.
#   - `ssl-enum-ciphers`'s protocol tables are read from nmap's structured
#     XML <table>/<elem> output, which is trusted; a flattened-text fallback
#     is used only if none of the expected protocol tables are present at
#     all (older nmap builds, or a script error).
#   - `sslv2`'s NSE output isn't as consistently documented as
#     ssl-enum-ciphers's; presence is inferred from the phrase "SSLv2
#     supported" in its flattened output text, matching the wording current
#     nmap builds use. Flag for re-verification if a live run ever shows an
#     unexpected all-False SSLv2 column against hosts known to support it.
#   - `ssl-cert`'s structured field names (subject/issuer commonName,
#     pubkey type/bits, sig_algo, validity notAfter) are read the same way,
#     with the same lower confidence and same "flag if implausible" caveat.
#   - Self-signed detection is a heuristic (subject commonName == issuer
#     commonName) -- it will not catch a cert whose issuer used a different
#     CN than the subject despite still being the same self-signed cert.
#   - Cert expiry ("Cert Days Until Expiry" / "Cert Expired") are live Excel
#     formulas against TODAY(), not values frozen at scan time, so they stay
#     accurate whenever the report is reopened -- unlike every other scored
#     column here, which reflects the scan run itself.
#   - "Weak Cipher Count"/"Weak Cipher Detail" only flag individual cipher
#     suites nmap itself grades C/D/F (e.g. RC4, 3DES, export-grade, NULL);
#     this is independent of, and in addition to, the legacy protocol-version
#     flags above -- a TLS 1.2 endpoint can still offer a weak cipher suite.
# =============================================================================

import argparse
import csv
import ipaddress
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))

# Same subnets in scope as the user's other sweep tools. Edit this list to
# change scope.
SUBNETS: List[str] = [
    "156.141.0.0/16",
    "156.140.0.0/16",
    "146.208.0.0/16",
    "141.184.0.0/16",
    "141.183.0.0/16",
    # "141.121.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
]

# Web/TLS ports in scope. Edit this list to add alternate HTTPS ports (e.g.
# 8443) -- masscan discovery, the nmap -p spec, and the "is this port in
# scope" checks all derive from it, same "edit this list" convention as
# SUBNETS.
TLS_PORTS: List[int] = [443]

DEFAULT_WORKERS = 12   # lower than ssh_vuln_scan.py's 16: ssl-enum-ciphers
                        # does one full TLS handshake per candidate cipher
                        # suite per protocol version, so each unit of work
                        # here is slower than a single SSH algorithm-list
                        # exchange. Raise if the host running this has
                        # headroom.
DEFAULT_RATE = 25000    # masscan packets/sec, same default as the sibling tools
DEFAULT_HOST_TIMEOUT = "45s"  # longer than ssh_vuln_scan.py's 30s, for the
                              # same reason as DEFAULT_WORKERS above
DEFAULT_RETRIES = 1

NMAP_SCRIPTS = "ssl-enum-ciphers,sslv2,ssl-cert"

# Protocol table keys as nmap's ssl-enum-ciphers names them, oldest first.
PROTOCOL_KEYS = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
# Row-dict / report field name for each protocol key above, same order.
PROTOCOL_FIELDS = ["sslv3", "tls10", "tls11", "tls12", "tls13"]
# The four protocols that count toward "legacy" -- SSLv2 (handled separately,
# it has no ssl-enum-ciphers table) plus everything ssl-enum-ciphers reports
# except TLS 1.2 and TLS 1.3.
LEGACY_FIELDS = ["sslv2", "sslv3", "tls10", "tls11"]
LEGACY_SCORE_WEIGHTS = {"sslv2": 1000, "sslv3": 100, "tls10": 10, "tls11": 1}

# nmap grades each cipher A (best) to F (worst); C/D/F are treated as weak
# for the purposes of the Weak Cipher Count/Detail columns below.
WEAK_CIPHER_GRADES = {"C", "D", "F"}

# New columns are appended at the end (not inserted among the original 15)
# so the Legacy Protocol Count / Legacy Score formulas' column-letter
# references never shift -- same convention ssh_vuln_scan.py's README
# documents for its own additions.
REPORT_HEADERS = [
    "Scan Date", "IP Address", "Hostname", "Port", "Banner",
    "SSLv2 Supported", "SSLv3 Supported", "TLS 1.0 Supported",
    "TLS 1.1 Supported", "TLS 1.2 Supported", "TLS 1.3 Supported",
    "Legacy Protocol Count", "Legacy Score", "Cipher Grade (Least Strength)",
    "Configured Subnet",
    "Cert Subject CN", "Cert Issuer CN", "Cert Self-Signed", "Cert Public Key",
    "Cert Signature Algorithm", "Cert Weak Signature Algo", "Cert Not After",
    "Cert Days Until Expiry", "Cert Expired",
    "Weak Cipher Count", "Weak Cipher Detail",
]
CSV_HEADERS = [
    "ScanDate", "IP", "Hostname", "Port", "Banner",
    "SSLv2Supported", "SSLv3Supported", "TLS10Supported", "TLS11Supported",
    "TLS12Supported", "TLS13Supported", "CipherGrade", "ConfiguredSubnet",
    "CertSubjectCN", "CertIssuerCN", "CertSelfSigned", "CertPublicKey",
    "CertSignatureAlgorithm", "CertWeakSignatureAlgo", "CertNotAfter",
    "WeakCipherCount", "WeakCipherDetail",
]


# =============================================================================
# LOGGING / PROGRESS DISPLAY (ported near-verbatim from ssh_vuln_scan.py /
# quantum_readiness_spray.py)
# =============================================================================

_progress_lock = threading.Lock()
_last_progress_len = 0


class ProgressAwareHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        global _last_progress_len
        with _progress_lock:
            if _last_progress_len:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")
                sys.stdout.flush()
            super().emit(record)
            _last_progress_len = 0


def setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("sslspray")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    console_handler = ProgressAwareHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def draw_progress_line(line: str) -> None:
    global _last_progress_len
    with _progress_lock:
        pad = max(0, _last_progress_len - len(line))
        sys.stdout.write("\r" + line + (" " * pad))
        sys.stdout.flush()
        _last_progress_len = len(line)


def finish_progress_line() -> None:
    global _last_progress_len
    with _progress_lock:
        if _last_progress_len:
            sys.stdout.write("\n")
            sys.stdout.flush()
        _last_progress_len = 0


def fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def render_bar(pct: Optional[float], width: int = 30) -> str:
    if pct is None:
        return "[" + "-" * width + "]  n/a"
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100.0)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {pct:5.1f}%"


# =============================================================================
# DEPENDENCY / VALIDATION HELPERS (mirrors ssh_vuln_scan.py)
# =============================================================================

def check_external_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def validate_subnets(raw_subnets: List[str], logger: logging.Logger) -> List[ipaddress.IPv4Network]:
    networks = []
    for entry in raw_subnets:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.error(f"Skipping invalid CIDR '{entry}': {exc}")
    return networks


def subnet_for_ip(ip: str, networks: List[ipaddress.IPv4Network]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    for net in networks:
        if addr in net:
            return str(net)
    return "UNKNOWN"


_XML_ILLEGAL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")


def resolve_hostname(ip: str, timeout: float) -> str:
    """Every other string field in a row (banner, cert subject/issuer CN,
    sig_algo) is read out of nmap's own XML output, so ElementTree parsing
    itself already guarantees it can't contain characters illegal in XML
    1.0 - nmap couldn't have produced valid XML containing them in the
    first place. This one doesn't go through nmap's XML at all: it's a raw
    reverse-DNS PTR lookup, so a misconfigured/malicious DNS record
    containing an XML-illegal control character would otherwise reach
    openpyxl unfiltered and crash .xlsx generation entirely (a bad PTR
    record shouldn't be able to lose the whole report)."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return _XML_ILLEGAL_RE.sub("", name)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


# =============================================================================
# PHASE 1: MASSCAN DISCOVERY (ported near-verbatim from ssh_vuln_scan.py)
# =============================================================================

class MasscanStatus:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.percent: Optional[float] = None
        self.eta: str = ""

    def update_from_line(self, line: str) -> None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s+done", line)
        eta_m = re.search(r"done,\s*([\d:]+)\s*remaining", line)
        with self.lock:
            if m:
                try:
                    self.percent = float(m.group(1))
                except ValueError:
                    pass
            if eta_m:
                self.eta = eta_m.group(1)


def _masscan_stderr_reader(proc: subprocess.Popen, status: MasscanStatus) -> None:
    buf = b""
    stream = proc.stderr
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                idx_r = buf.find(b"\r")
                idx_n = buf.find(b"\n")
                candidates = [i for i in (idx_r, idx_n) if i != -1]
                if not candidates:
                    break
                idx = min(candidates)
                line = buf[:idx].decode(errors="ignore").strip()
                buf = buf[idx + 1:]
                if line:
                    status.update_from_line(line)
    except (ValueError, OSError):
        pass


def build_masscan_command(masscan_path: str, subnets: List[str], rate: int,
                           output_file: str, interface: Optional[str],
                           ports: List[int]) -> List[str]:
    port_spec = "T:" + ",".join(str(p) for p in ports)
    cmd = [masscan_path, "-p", port_spec, "--rate", str(rate), "-oL", output_file]
    if interface:
        cmd += ["-e", interface]
    cmd += subnets
    return cmd


def parse_masscan_list_output(path: str, start_offset: int = 0) -> Tuple[List[Tuple[str, int, str]], int]:
    records: List[Tuple[str, int, str]] = []
    if not os.path.exists(path):
        return records, start_offset
    with open(path, "rb") as f:
        f.seek(start_offset)
        chunk = f.read()
    if not chunk:
        return records, start_offset
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return records, start_offset
    usable, new_offset = chunk[:last_newline + 1], start_offset + last_newline + 1
    for raw_line in usable.split(b"\n"):
        line = raw_line.decode(errors="ignore").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        status, proto, port_s, ip, _ts = parts[:5]
        if status != "open":
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        records.append((ip, port, proto))
    return records, new_offset


def run_masscan_phase1(masscan_path: str, subnets: List[str], rate: int,
                        output_file: str, interface: Optional[str],
                        ports: List[int], logger: logging.Logger,
                        stop_event: threading.Event
                        ) -> List[Tuple[str, int, str]]:
    cmd = build_masscan_command(masscan_path, subnets, rate, output_file, interface, ports)
    logger.info("Phase 1 - DISCOVERY starting")
    logger.debug(f"Masscan command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"masscan executable not found at '{masscan_path}'.")
        return []
    except PermissionError as exc:
        logger.error(f"Permission error launching masscan: {exc}. "
                      f"Masscan typically requires root/administrator privileges.")
        return []
    except OSError as exc:
        logger.error(f"Failed to launch masscan: {exc}")
        return []

    status = MasscanStatus()
    reader_thread = threading.Thread(target=_masscan_stderr_reader, args=(proc, status), daemon=True)
    reader_thread.start()

    port_set = set(ports)
    start_time = time.time()
    tls_count = 0
    offset = 0
    seen: set = set()

    def _drain_new_records() -> None:
        nonlocal offset, tls_count
        new_records, offset = parse_masscan_list_output(output_file, offset)
        for ip, port, _proto in new_records:
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)
            if port in port_set:
                tls_count += 1

    try:
        while True:
            if stop_event.is_set():
                logger.warning("Interrupt received, terminating masscan...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break

            retcode = proc.poll()
            _drain_new_records()

            elapsed = time.time() - start_time
            with status.lock:
                pct = status.percent
                eta = status.eta

            bar = render_bar(pct)
            eta_str = eta if eta else "n/a"
            line = (f"Phase 1 - DISCOVERY {bar} | TLS hosts found: {tls_count} | "
                     f"Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta_str}")
            draw_progress_line(line)

            if retcode is not None:
                time.sleep(0.3)
                _drain_new_records()
                break
            time.sleep(0.5)
    finally:
        finish_progress_line()

    if proc.returncode not in (0, None) and not stop_event.is_set():
        logger.warning(f"masscan exited with return code {proc.returncode}. "
                        f"Results collected so far will still be used.")

    final_records, _ = parse_masscan_list_output(output_file, 0)
    logger.info(f"Phase 1 - DISCOVERY complete. TLS-port hits: {tls_count}, "
                f"elapsed: {fmt_elapsed(time.time() - start_time)}")
    return final_records


# =============================================================================
# XML PARSING (nmap -oX output, one host at a time in Phase 2)
# =============================================================================

def _has_table(script_elem, key: str) -> bool:
    return _find_table(script_elem, key) is not None


def _find_table(parent, key: str):
    for table in parent.findall("table"):
        if table.get("key") == key:
            return table
    return None


def _elem_value(parent, key: str) -> Optional[str]:
    for elem in parent.findall("elem"):
        if elem.get("key") == key:
            return elem.text or ""
    return None


def _regex_field(text: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, text)
    return m.group(1).strip() if m else None


def _protocols_present_fallback(output_text: str) -> Dict[str, bool]:
    """Fallback if ssl-enum-ciphers's structured <table> children are absent
    entirely: a protocol is considered supported if its name appears as its
    own line (nmap's flattened text lists each supported protocol as a
    top-level heading line, e.g. '  TLSv1.2: ')."""
    lines = {line.strip().rstrip(":").strip() for line in output_text.splitlines()}
    return {key: key in lines for key in PROTOCOL_KEYS}


def _weak_ciphers_in_protocol_table(protocol_key: str, protocol_table) -> List[Tuple[str, str, str]]:
    """Returns [(protocol, cipher_name, grade)] for every cipher graded C/D/F
    under this one protocol's <table key="ciphers"> block. Only available
    from the structured XML form -- there is no flattened-text fallback for
    per-cipher grades, only for the least strength summary."""
    ciphers_tbl = _find_table(protocol_table, "ciphers")
    if ciphers_tbl is None:
        return []
    out = []
    for entry in ciphers_tbl.findall("table"):
        name = _elem_value(entry, "name") or ""
        grade = _elem_value(entry, "strength") or ""
        if name and grade in WEAK_CIPHER_GRADES:
            out.append((protocol_key, name, grade))
    return out


def parse_ssl_enum_ciphers(script_elem) -> Tuple[Dict[str, bool], Optional[str], List[Tuple[str, str, str]]]:
    """Returns ({protocol_key: supported}, least_strength_grade_or_None,
    [(protocol, cipher_name, grade), ...] for every weak cipher found)."""
    present: Dict[str, bool] = {}
    weak_ciphers: List[Tuple[str, str, str]] = []
    for key in PROTOCOL_KEYS:
        tbl = _find_table(script_elem, key)
        present[key] = tbl is not None
        if tbl is not None:
            weak_ciphers.extend(_weak_ciphers_in_protocol_table(key, tbl))

    if not any(present.values()):
        output = script_elem.get("output", "") or ""
        present = _protocols_present_fallback(output)
        # weak_ciphers stays empty in this fallback path -- per-cipher grades
        # aren't recoverable from the flattened text, only protocol presence.

    least_strength = _elem_value(script_elem, "least strength")
    if least_strength is None:
        output = script_elem.get("output", "") or ""
        m = re.search(r"least strength:\s*([A-F])", output)
        least_strength = m.group(1) if m else None

    return present, least_strength, weak_ciphers


def parse_sslv2(script_elem) -> bool:
    """No documented structured-table output for this NSE script to lean
    on, so this is inferred from the flattened output text -- see the
    LIMITATIONS note at the top of this file."""
    output = script_elem.get("output", "") or ""
    return "sslv2 supported" in output.lower()


def parse_ssl_cert(script_elem) -> dict:
    """Returns cert subject/issuer/key/signature/validity fields. Tries the
    structured <table>/<elem> form first (subject/issuer/pubkey/validity
    tables, top-level sig_algo elem); falls back to regexing ssl-cert's
    flattened text only if none of the structured fields were found at all.
    Confidence on the exact structured field names is lower than for
    ssl-enum-ciphers -- flag for re-verification against a live nmap install
    if a real run ever shows implausible blanks here."""
    subject_tbl = _find_table(script_elem, "subject")
    issuer_tbl = _find_table(script_elem, "issuer")
    pubkey_tbl = _find_table(script_elem, "pubkey")
    validity_tbl = _find_table(script_elem, "validity")

    subject_cn = _elem_value(subject_tbl, "commonName") if subject_tbl is not None else None
    issuer_cn = _elem_value(issuer_tbl, "commonName") if issuer_tbl is not None else None
    pubkey_type = _elem_value(pubkey_tbl, "type") if pubkey_tbl is not None else None
    pubkey_bits = _elem_value(pubkey_tbl, "bits") if pubkey_tbl is not None else None
    sig_algo = _elem_value(script_elem, "sig_algo")
    not_after = _elem_value(validity_tbl, "notAfter") if validity_tbl is not None else None

    if subject_cn is None and issuer_cn is None and not_after is None:
        output = script_elem.get("output", "") or ""
        subject_cn = _regex_field(output, r"Subject:.*?commonName=([^/\n,]+)")
        issuer_cn = _regex_field(output, r"Issuer:.*?commonName=([^/\n,]+)")
        sig_algo = sig_algo or _regex_field(output, r"Signature Algorithm:\s*(\S+)")
        not_after = _regex_field(output, r"Not valid after:\s*(\S+)")
        pubkey_type = pubkey_type or _regex_field(output, r"Public Key type:\s*(\S+)")
        pubkey_bits = pubkey_bits or _regex_field(output, r"Public Key bits:\s*(\d+)")

    self_signed = bool(subject_cn and issuer_cn and subject_cn.strip().lower() == issuer_cn.strip().lower())
    weak_sig_algo = bool(sig_algo and re.search(r"sha1|md5|md2", sig_algo, re.IGNORECASE))
    pubkey = ""
    if pubkey_type and pubkey_bits:
        pubkey = f"{pubkey_type.upper()} {pubkey_bits}"
    elif pubkey_type:
        pubkey = pubkey_type.upper()

    return {
        "subject_cn": subject_cn or "", "issuer_cn": issuer_cn or "",
        "self_signed": self_signed, "pubkey": pubkey,
        "sig_algo": sig_algo or "", "weak_sig_algo": weak_sig_algo,
        "not_after": not_after or "",
    }


def parse_port(port_el, ip: str, hostname: str, scan_date: str,
               subnet_label: str) -> Optional[dict]:
    """Returns a row dict for this port, or None if it isn't a countable
    TLS endpoint (not open, or open but nothing here actually speaks
    SSL/TLS)."""
    state_el = port_el.find("state")
    if state_el is None or state_el.get("state") != "open":
        return None  # closed / filtered / open|filtered - nothing to audit

    service_el = port_el.find("service")

    banner = ""
    if service_el is not None:
        product = service_el.get("product", "")
        version = service_el.get("version", "")
        extrainfo = service_el.get("extrainfo", "")
        banner = " ".join(p for p in (product, version) if p)
        if extrainfo:
            banner = f"{banner} ({extrainfo})" if banner else f"({extrainfo})"

    protocols: Dict[str, bool] = {f: False for f in PROTOCOL_FIELDS}
    cipher_grade: Optional[str] = None
    weak_ciphers: List[Tuple[str, str, str]] = []
    sslv2 = False
    cert = {
        "subject_cn": "", "issuer_cn": "", "self_signed": False, "pubkey": "",
        "sig_algo": "", "weak_sig_algo": False, "not_after": "",
    }

    for script in port_el.findall("script"):
        sid = script.get("id")
        if sid == "ssl-enum-ciphers":
            present, cipher_grade, weak_ciphers = parse_ssl_enum_ciphers(script)
            for key, field_name in zip(PROTOCOL_KEYS, PROTOCOL_FIELDS):
                protocols[field_name] = present.get(key, False)
        elif sid == "sslv2":
            sslv2 = parse_sslv2(script)
        elif sid == "ssl-cert":
            cert = parse_ssl_cert(script)

    # Guard against counting a non-TLS service that happens to be sitting on
    # a configured TLS port as a real endpoint - a masscan hit only proves
    # the port is open, not that TLS is what's listening there. This checks
    # for actual usable evidence (a confirmed protocol, a cipher grade, or
    # any cert field), not just "did a script element appear at all" -
    # ssl-enum-ciphers/sslv2/ssl-cert can each appear in the XML and still
    # have produced nothing (e.g. output="ERROR: ..." after a connection
    # reset mid-handshake), which must not be reported as a clean,
    # zero-findings endpoint.
    has_usable_data = (
        sslv2 or any(protocols.values()) or cipher_grade is not None
        or any([cert["subject_cn"], cert["issuer_cn"], cert["pubkey"],
                cert["sig_algo"], cert["not_after"]])
    )
    if not has_usable_data:
        return None

    port_num = int(port_el.get("portid", "0"))
    legacy_count = sum(1 for f in LEGACY_FIELDS if (protocols.get(f, False) if f != "sslv2" else sslv2))
    legacy_score = sum(w for f, w in LEGACY_SCORE_WEIGHTS.items()
                        if (sslv2 if f == "sslv2" else protocols.get(f, False)))
    weak_cipher_detail = " | ".join(f"{proto}: {name} ({grade})" for proto, name, grade in weak_ciphers)

    return {
        "scan_date": scan_date, "ip": ip, "hostname": hostname, "port": port_num,
        "banner": banner, "sslv2": sslv2,
        "sslv3": protocols["sslv3"], "tls10": protocols["tls10"],
        "tls11": protocols["tls11"], "tls12": protocols["tls12"],
        "tls13": protocols["tls13"], "cipher_grade": cipher_grade or "",
        "legacy_count": legacy_count, "legacy_score": legacy_score,
        "subnet": subnet_label,
        "cert_subject_cn": cert["subject_cn"], "cert_issuer_cn": cert["issuer_cn"],
        "cert_self_signed": cert["self_signed"], "cert_pubkey": cert["pubkey"],
        "cert_sig_algo": cert["sig_algo"], "cert_weak_sig_algo": cert["weak_sig_algo"],
        "cert_not_after": cert["not_after"],
        "weak_cipher_count": len(weak_ciphers), "weak_cipher_detail": weak_cipher_detail,
    }


def parse_xml_file(xml_path: str, scan_date: str, hostname_override: str,
                    subnet_label: str, tls_ports: List[int]) -> List[dict]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    rows: List[dict] = []
    port_set = set(tls_ports)
    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if ip is None:
            continue

        hostname = hostname_override
        if not hostname:
            hostnames_el = host_elem.find("hostnames")
            if hostnames_el is not None:
                chosen = hostnames_el.find("hostname[@type='PTR']")
                if chosen is None:
                    chosen = hostnames_el.find("hostname")
                if chosen is not None:
                    hostname = chosen.get("name", "")

        ports_el = host_elem.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            try:
                portid = int(port_el.get("portid", "-1"))
            except ValueError:
                continue
            if portid not in port_set:
                continue
            row = parse_port(port_el, ip, hostname, scan_date, subnet_label)
            if row is not None:
                rows.append(row)
    return rows


# =============================================================================
# PHASE 2: PER-HOST NMAP WORKER POOL
# =============================================================================

@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    subnet: str = "UNKNOWN"
    ports: List[int] = field(default_factory=list)


@dataclass
class Phase2Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    total: int = 0
    completed: int = 0
    active_workers: int = 0
    tls_confirmed: int = 0
    legacy_found: int = 0


def _run_nmap_single_host(nmap_path: str, ip: str, ports: List[int],
                           xml_path: str, host_timeout: str) -> bool:
    """Runs nmap against exactly one host, covering every TLS port that
    Phase 1 found open on it in a single invocation. -Pn/-n skip nmap's own
    host discovery and DNS - both already done in Phase 1 / the resolve
    step. Returns True if nmap ran (regardless of whether TLS was found),
    False on a launch failure."""
    port_spec = ",".join(str(p) for p in sorted(ports))
    cmd = [nmap_path, "-p", port_spec, "-Pn", "-n", "-sV",
           "--host-timeout", host_timeout,
           "--script", NMAP_SCRIPTS, "-oX", xml_path, ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (FileNotFoundError, OSError):
        return False


def scan_one_host(host: DiscoveredHost, args: argparse.Namespace,
                   logger: logging.Logger) -> List[dict]:
    # Outermost guard on top of the finer-grained one below: nothing in this
    # function, including temp-file creation itself, may be allowed to
    # propagate out and take the rest of the batch down with it.
    try:
        return _scan_one_host_inner(host, args, logger)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"scan_one_host({host.ip}) failed unexpectedly: {exc}")
        return []


def _scan_one_host_inner(host: DiscoveredHost, args: argparse.Namespace,
                          logger: logging.Logger) -> List[dict]:
    scan_date = datetime.now().strftime("%Y-%m-%d")
    fd, xml_path = tempfile.mkstemp(prefix="sslspray_", suffix=".xml")
    os.close(fd)
    try:
        rows: List[dict] = []
        for attempt in range(max(1, args.retries + 1)):
            # Broad except is deliberate here, matching the sibling scripts'
            # "one bad host must not kill the scan" rule: nmap failing to
            # even write the -oX file (killed by --host-timeout mid-write, a
            # disk hiccup, a permissions problem) must not propagate past
            # this one host's result.
            try:
                ok = _run_nmap_single_host(args.nmap_path, host.ip, host.ports, xml_path, args.host_timeout)
                rows = parse_xml_file(xml_path, scan_date, host.hostname, host.subnet, args.tls_ports) if ok else []
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"scan_one_host({host.ip}) attempt {attempt + 1} failed: {exc}")
                rows = []
            if rows:
                break
            # empty result with no exception: either genuinely not TLS on
            # any of these ports, or a transient miss - only the latter
            # benefits from a retry, but a deterministic non-TLS result
            # costs nothing extra to retry either, so the same bounded loop
            # covers both cases.
        if args.keep_temp:
            # Broad except for the same reason as the retry loop above: this
            # is bookkeeping on top of an already-successful scan, and must
            # not be able to take down the rest of the batch if it fails.
            try:
                keep_dir = os.path.join(args.output_dir, f"nmap_xml_{scan_date}")
                os.makedirs(keep_dir, exist_ok=True)
                dest = os.path.join(keep_dir, f"{host.ip.replace(':', '_')}.xml")
                shutil.move(xml_path, dest)
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"--keep-temp: could not save XML for {host.ip}: {exc}")
        return rows
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


def render_phase2_line(stats: Phase2Stats, start_time: float) -> str:
    with stats.lock:
        completed = stats.completed
        total = stats.total
        active = stats.active_workers
        confirmed = stats.tls_confirmed
        legacy = stats.legacy_found
    pct = (completed / total * 100.0) if total else 0.0
    elapsed = time.time() - start_time
    if 0 < completed < total:
        eta = fmt_elapsed((elapsed / completed) * (total - completed))
    elif completed >= total and total > 0:
        eta = "00:00:00"
    else:
        eta = "n/a"
    bar = render_bar(pct)
    return (f"Phase 2 - TLS AUDIT {bar} | Completed: {completed}/{total} | "
            f"Workers: {active} | Confirmed TLS endpoints: {confirmed} | "
            f"With legacy protocol: {legacy} | Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta}")


def run_phase2(hosts: List[DiscoveredHost], args: argparse.Namespace,
               logger: logging.Logger, stop_event: threading.Event) -> List[dict]:
    stats = Phase2Stats()
    stats.total = len(hosts)
    rows: List[dict] = []
    start_time = time.time()
    logger.info(f"Phase 2 - TLS AUDIT starting ({stats.total} hosts, {args.workers} workers)")

    def wrapped(host: DiscoveredHost) -> List[dict]:
        with stats.lock:
            stats.active_workers += 1
        try:
            return scan_one_host(host, args, logger)
        finally:
            with stats.lock:
                stats.active_workers -= 1

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(wrapped, host): host for host in hosts}
        try:
            for future in as_completed(futures):
                host_rows = future.result()
                with stats.lock:
                    stats.completed += 1
                    for row in host_rows:
                        stats.tls_confirmed += 1
                        if row["legacy_count"] > 0:
                            stats.legacy_found += 1
                rows.extend(host_rows)
                draw_progress_line(render_phase2_line(stats, start_time))
                if stop_event.is_set():
                    logger.warning("Interrupt received, cancelling remaining audits...")
                    for f in futures:
                        f.cancel()
                    break
        finally:
            finish_progress_line()

    logger.info(f"Phase 2 - TLS AUDIT complete. {stats.completed}/{stats.total} hosts "
                f"probed, {stats.tls_confirmed} confirmed TLS endpoint(s), "
                f"finished in {fmt_elapsed(time.time() - start_time)}.")
    return rows


# =============================================================================
# OUTPUT SANITIZATION
# =============================================================================
# hostname (reverse-DNS PTR), banner, and every cert field are sourced from
# whatever the scanned host chooses to present - that's exactly what this
# tool is auditing, so they're attacker-controlled by design. Opening the
# generated report in Excel/LibreOffice/Google Sheets is this tool's entire
# purpose, and any of those will auto-evaluate a cell that starts with
# =, +, -, or @ as a formula (CWE-1236, "CSV/Excel formula injection") -
# a malicious cert Subject CN or PTR record could otherwise run a command
# or exfiltrate data from the analyst's own machine the moment the report
# is opened. The standard mitigation (also what openpyxl itself needs here,
# since assigning a leading "=" to a cell.value makes openpyxl treat it as
# a live formula) is prefixing a single quote, which forces plain-text
# interpretation everywhere without otherwise changing the visible value.

_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _neutralize_formula(value):
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGER_CHARS):
        return "'" + value
    return value


# =============================================================================
# CSV
# =============================================================================

def write_csv(rows: List[dict], csv_path: str, logger: logging.Logger) -> None:
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADERS)
            for r in rows:
                w.writerow([
                    r["scan_date"], r["ip"], _neutralize_formula(r["hostname"]), r["port"],
                    _neutralize_formula(r["banner"]),
                    "TRUE" if r["sslv2"] else "FALSE",
                    "TRUE" if r["sslv3"] else "FALSE",
                    "TRUE" if r["tls10"] else "FALSE",
                    "TRUE" if r["tls11"] else "FALSE",
                    "TRUE" if r["tls12"] else "FALSE",
                    "TRUE" if r["tls13"] else "FALSE",
                    r["cipher_grade"], r.get("subnet", ""),
                    _neutralize_formula(r["cert_subject_cn"]), _neutralize_formula(r["cert_issuer_cn"]),
                    "TRUE" if r["cert_self_signed"] else "FALSE",
                    _neutralize_formula(r["cert_pubkey"]), _neutralize_formula(r["cert_sig_algo"]),
                    "TRUE" if r["cert_weak_sig_algo"] else "FALSE",
                    _neutralize_formula(r["cert_not_after"]),
                    r["weak_cipher_count"], _neutralize_formula(r["weak_cipher_detail"]),
                ])
        logger.info(f"CSV saved to: {csv_path}")
    except OSError as exc:
        logger.error(f"Failed to write CSV to {csv_path}: {exc}")


def _csv_field(r: dict, key: str, default: str = "") -> str:
    """r.get(key, default) isn't enough: csv.DictReader maps a short row's
    missing trailing columns to None (its restval), not the dict's default,
    so a hand-edited or older-format CSV can still hand back None for a key
    that IS present. Treat missing key, None, and blank the same way."""
    return r.get(key) or default


def _csv_flag(r: dict, key: str) -> bool:
    return _csv_field(r, key).strip().upper() == "TRUE"


def _csv_int(r: dict, key: str, default: int = 0) -> int:
    raw = _csv_field(r, key).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def read_rows_from_csv(csv_path: str) -> List[dict]:
    """Rebuild the same row-dict shape parse_port() produces, from a
    previously-written (or hand-edited) CSV. Used by --from-csv. Every
    field goes through _csv_field/_csv_flag/_csv_int rather than direct
    dict indexing, so one blank cell or one missing column in a hand-edited
    CSV degrades that field to a default instead of crashing the whole
    --from-csv run."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            sslv2 = _csv_flag(r, "SSLv2Supported")
            sslv3 = _csv_flag(r, "SSLv3Supported")
            tls10 = _csv_flag(r, "TLS10Supported")
            tls11 = _csv_flag(r, "TLS11Supported")
            tls12 = _csv_flag(r, "TLS12Supported")
            tls13 = _csv_flag(r, "TLS13Supported")
            flags = {"sslv2": sslv2, "sslv3": sslv3, "tls10": tls10, "tls11": tls11}
            legacy_count = sum(1 for v in flags.values() if v)
            legacy_score = sum(w for field_name, w in LEGACY_SCORE_WEIGHTS.items() if flags[field_name])
            rows.append({
                "scan_date": _csv_field(r, "ScanDate"), "ip": _csv_field(r, "IP"),
                "hostname": _csv_field(r, "Hostname"),
                "port": _csv_int(r, "Port"), "banner": _csv_field(r, "Banner"),
                "sslv2": sslv2, "sslv3": sslv3, "tls10": tls10, "tls11": tls11,
                "tls12": tls12, "tls13": tls13,
                "cipher_grade": _csv_field(r, "CipherGrade"),
                "subnet": _csv_field(r, "ConfiguredSubnet"),
                "legacy_count": legacy_count, "legacy_score": legacy_score,
                "cert_subject_cn": _csv_field(r, "CertSubjectCN"),
                "cert_issuer_cn": _csv_field(r, "CertIssuerCN"),
                "cert_self_signed": _csv_flag(r, "CertSelfSigned"),
                "cert_pubkey": _csv_field(r, "CertPublicKey"),
                "cert_sig_algo": _csv_field(r, "CertSignatureAlgorithm"),
                "cert_weak_sig_algo": _csv_flag(r, "CertWeakSignatureAlgo"),
                "cert_not_after": _csv_field(r, "CertNotAfter"),
                "weak_cipher_count": _csv_int(r, "WeakCipherCount"),
                "weak_cipher_detail": _csv_field(r, "WeakCipherDetail"),
            })
    return rows


# =============================================================================
# XLSX report
# =============================================================================

_CERT_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",       # nmap's normal ISO-ish notAfter
    "%Y-%m-%dT%H:%M:%S%z",     # same, with a timezone offset
    "%b %d %H:%M:%S %Y %Z",    # openssl-style, seen in some flattened-text fallbacks
)


def _parse_cert_date(value: str):
    """Best-effort parse of ssl-cert's notAfter field into a date for the
    xlsx cell. Returns None (leaving the cell blank) if the format isn't one
    of the ones this script has actually seen, rather than guessing."""
    if not value:
        return None
    for fmt in _CERT_DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def build_workbook(rows: List[dict]):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.formatting.rule import CellIsRule, FormulaRule, ColorScaleRule
    from openpyxl.chart import BarChart, Reference
    from openpyxl.chart.marker import DataPoint
    from openpyxl.chart.shapes import GraphicalProperties
    from openpyxl.utils import get_column_letter

    RED_FILL = PatternFill("solid", fgColor="FFC7CE")
    RED_FONT = Font(color="9C0006", bold=True)
    AMBER_FILL = PatternFill("solid", fgColor="FFEB9C")
    AMBER_FONT = Font(color="9C6500")
    GREEN_FILL = PatternFill("solid", fgColor="C6EFCE")
    GREEN_FONT = Font(color="006100")
    NEUTRAL_FILL = PatternFill("solid", fgColor="DCE6F1")
    HEADER_FILL = PatternFill("solid", fgColor="1F3864")
    HEADER_FONT = Font(color="FFFFFF", bold=True, size=18)
    SECTION_FONT = Font(bold=True, size=13)
    LABEL_FONT = Font(bold=True, size=10, color="595959")
    SUBTEXT_FONT = Font(italic=True, size=9, color="808080")
    TILE_NUM_FONT = Font(bold=True, size=32)
    THIN_BORDER = Border(bottom=Side(style="thin", color="BFBFBF"))
    RED_BAR = "FFC7CE"
    AMBER_BAR = "FFEB9C"

    COL = {name: i + 1 for i, name in enumerate(REPORT_HEADERS)}

    def build_report_sheet(wb):
        ws = wb.create_sheet("Report")
        ws["A1"] = "SSL/TLS Protocol Scan - Detailed Report"
        ws["A1"].font = Font(bold=True, size=14)

        for c, name in enumerate(REPORT_HEADERS, start=1):
            cell = ws.cell(row=2, column=c, value=name)
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="D9D9D9")

        for i, r in enumerate(rows):
            row_num = 3 + i
            try:
                date_val = datetime.strptime(r["scan_date"], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                date_val = r["scan_date"]
            ws.cell(row=row_num, column=COL["Scan Date"], value=date_val).number_format = "yyyy-mm-dd"
            ws.cell(row=row_num, column=COL["IP Address"], value=r["ip"])
            ws.cell(row=row_num, column=COL["Hostname"], value=_neutralize_formula(r["hostname"]) or None)
            ws.cell(row=row_num, column=COL["Port"], value=r["port"])
            ws.cell(row=row_num, column=COL["Banner"], value=_neutralize_formula(r["banner"]) or None)
            ws.cell(row=row_num, column=COL["SSLv2 Supported"], value=r["sslv2"])
            ws.cell(row=row_num, column=COL["SSLv3 Supported"], value=r["sslv3"])
            ws.cell(row=row_num, column=COL["TLS 1.0 Supported"], value=r["tls10"])
            ws.cell(row=row_num, column=COL["TLS 1.1 Supported"], value=r["tls11"])
            ws.cell(row=row_num, column=COL["TLS 1.2 Supported"], value=r["tls12"])
            ws.cell(row=row_num, column=COL["TLS 1.3 Supported"], value=r["tls13"])

            sslv2_col = get_column_letter(COL["SSLv2 Supported"])
            tls11_col = get_column_letter(COL["TLS 1.1 Supported"])
            sslv3_col = get_column_letter(COL["SSLv3 Supported"])
            tls10_col = get_column_letter(COL["TLS 1.0 Supported"])
            ws.cell(row=row_num, column=COL["Legacy Protocol Count"],
                    value=f"=COUNTIF({sslv2_col}{row_num}:{tls11_col}{row_num},TRUE)")
            ws.cell(row=row_num, column=COL["Legacy Score"],
                    value=(f"=IF({sslv2_col}{row_num}=TRUE,1000,0)"
                           f"+IF({sslv3_col}{row_num}=TRUE,100,0)"
                           f"+IF({tls10_col}{row_num}=TRUE,10,0)"
                           f"+IF({tls11_col}{row_num}=TRUE,1,0)"))
            ws.cell(row=row_num, column=COL["Cipher Grade (Least Strength)"], value=r["cipher_grade"] or None)
            ws.cell(row=row_num, column=COL["Configured Subnet"], value=r.get("subnet") or None)

            ws.cell(row=row_num, column=COL["Cert Subject CN"], value=_neutralize_formula(r["cert_subject_cn"]) or None)
            ws.cell(row=row_num, column=COL["Cert Issuer CN"], value=_neutralize_formula(r["cert_issuer_cn"]) or None)
            ws.cell(row=row_num, column=COL["Cert Self-Signed"], value=r["cert_self_signed"])
            ws.cell(row=row_num, column=COL["Cert Public Key"], value=_neutralize_formula(r["cert_pubkey"]) or None)
            ws.cell(row=row_num, column=COL["Cert Signature Algorithm"], value=_neutralize_formula(r["cert_sig_algo"]) or None)
            ws.cell(row=row_num, column=COL["Cert Weak Signature Algo"], value=r["cert_weak_sig_algo"])

            not_after_col = get_column_letter(COL["Cert Not After"])
            not_after_cell = ws.cell(row=row_num, column=COL["Cert Not After"])
            not_after_val = _parse_cert_date(r["cert_not_after"])
            if not_after_val is not None:
                not_after_cell.value = not_after_val
                not_after_cell.number_format = "yyyy-mm-dd"
            ws.cell(row=row_num, column=COL["Cert Days Until Expiry"],
                    value=f'=IF({not_after_col}{row_num}="","",{not_after_col}{row_num}-TODAY())')
            ws.cell(row=row_num, column=COL["Cert Expired"],
                    value=f'=IF({not_after_col}{row_num}="","",{not_after_col}{row_num}<TODAY())')

            ws.cell(row=row_num, column=COL["Weak Cipher Count"], value=r["weak_cipher_count"])
            ws.cell(row=row_num, column=COL["Weak Cipher Detail"], value=_neutralize_formula(r["weak_cipher_detail"]) or None)

        last_row = 2 + len(rows) if rows else 2
        ws.freeze_panes = "A3"
        if rows:
            last_col = get_column_letter(len(REPORT_HEADERS))
            ws.auto_filter.ref = f"A2:{last_col}{last_row}"

        widths = {"A": 12, "B": 16, "C": 24, "D": 8, "E": 32, "F": 12,
                  "G": 12, "H": 12, "I": 12, "J": 12, "K": 12, "L": 16,
                  "M": 14, "N": 14, "O": 18, "P": 20, "Q": 20, "R": 14,
                  "S": 14, "T": 24, "U": 16, "V": 14, "W": 12, "X": 12,
                  "Y": 12, "Z": 60}
        for col, w in widths.items():
            ws.column_dimensions[col].width = w
        return ws

    def add_tile(ws, top_row, left_col, label, number_formula, subtext_formula, number_format=None):
        c1 = get_column_letter(left_col)
        c2 = get_column_letter(left_col + 1)

        num_cell = ws[f"{c1}{top_row}"]
        ws.merge_cells(f"{c1}{top_row}:{c2}{top_row}")
        num_cell.value = number_formula
        num_cell.font = TILE_NUM_FONT
        num_cell.alignment = Alignment(horizontal="center")
        if number_format:
            num_cell.number_format = number_format

        lbl_cell = ws[f"{c1}{top_row + 1}"]
        ws.merge_cells(f"{c1}{top_row + 1}:{c2}{top_row + 1}")
        lbl_cell.value = label
        lbl_cell.font = LABEL_FONT
        lbl_cell.alignment = Alignment(horizontal="center")

        sub_cell = ws[f"{c1}{top_row + 2}"]
        ws.merge_cells(f"{c1}{top_row + 2}:{c2}{top_row + 2}")
        sub_cell.value = subtext_formula
        sub_cell.font = SUBTEXT_FONT
        sub_cell.alignment = Alignment(horizontal="center")

        return num_cell.coordinate

    def build_overview_sheet(wb):
        ws = wb.create_sheet("Overview")
        ws.sheet_view.showGridLines = False

        ws.merge_cells("A1:I1")
        ws["A1"] = "SSL/TLS PROTOCOL POSTURE — SUBNET AUDIT"
        ws["A1"].font = HEADER_FONT
        ws["A1"].fill = HEADER_FILL
        ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 30

        ws.merge_cells("A2:I2")
        ws["A2"] = ('="Report generated: "&TEXT(MAX(Report!$A$3:$A$100000),"mmmm d, yyyy")'
                     '&"   |   Full per-host detail on the Report tab"')
        ws["A2"].font = SUBTEXT_FONT
        ws["A2"].alignment = Alignment(horizontal="center")
        ws.row_dimensions[2].height = 18

        def pct_of_hosts(cell_ref):
            return f'=IFERROR(TEXT({cell_ref}/$B$4,"0%")&" of scanned endpoints","—")'

        def coord(top_row, left_col):
            return f"{get_column_letter(left_col)}{top_row}"

        hosts_cell = add_tile(ws, 4, 2, "TLS ENDPOINTS SCANNED",
                               "=COUNTA(Report!$B$3:$B$100000)",
                               '="Subnet scan — "&TEXT(MAX(Report!$A$3:$A$100000),"mmm d, yyyy")')
        ws[hosts_cell].fill = NEUTRAL_FILL

        add_tile(ws, 4, 5, "SUPPORTING SSLv2 (CRITICAL)",
                 "=COUNTIF(Report!$F$3:$F$100000,TRUE)", pct_of_hosts(coord(4, 5)))
        add_tile(ws, 4, 8, "SUPPORTING SSLv3 (CRITICAL)",
                 "=COUNTIF(Report!$G$3:$G$100000,TRUE)", pct_of_hosts(coord(4, 8)))
        add_tile(ws, 8, 2, "SUPPORTING TLS 1.0 (LEGACY)",
                 "=COUNTIF(Report!$H$3:$H$100000,TRUE)", pct_of_hosts(coord(8, 2)))
        add_tile(ws, 8, 5, "SUPPORTING TLS 1.1 (LEGACY)",
                 "=COUNTIF(Report!$I$3:$I$100000,TRUE)", pct_of_hosts(coord(8, 5)))
        tls12_cell = add_tile(ws, 8, 8, "SUPPORTING TLS 1.2",
                               "=COUNTIF(Report!$J$3:$J$100000,TRUE)", pct_of_hosts(coord(8, 8)))
        ws[tls12_cell].fill = NEUTRAL_FILL
        tls13_cell = add_tile(ws, 12, 2, "SUPPORTING TLS 1.3",
                               "=COUNTIF(Report!$K$3:$K$100000,TRUE)", pct_of_hosts(coord(12, 2)))
        ws[tls13_cell].fill = NEUTRAL_FILL

        # "Fully modern" = no legacy protocol AND at least one of TLS 1.2/1.3
        # confirmed - not just "no legacy protocol" on its own, which would
        # also match an endpoint whose protocol enumeration was inconclusive
        # (all six protocol columns False). Built from three COUNTIFS
        # (inclusion-exclusion for the TLS1.2-OR-TLS1.3 condition) rather
        # than SUMPRODUCT: SUMPRODUCT's array arithmetic coerces the ~99997
        # blank filler rows below the real data to 0/FALSE, which would
        # wrongly match a "=FALSE" comparison and count every blank row as
        # modern; COUNTIFS' exact-type matching does not have this problem
        # (blank cells never match a TRUE/FALSE criterion), matching every
        # other COUNTIF/COUNTIFS tile on this sheet.
        no_legacy = ('Report!$F$3:$F$100000,FALSE,Report!$G$3:$G$100000,FALSE,'
                     'Report!$H$3:$H$100000,FALSE,Report!$I$3:$I$100000,FALSE')
        clean_formula = (
            f'=COUNTIFS({no_legacy},Report!$J$3:$J$100000,TRUE)'
            f'+COUNTIFS({no_legacy},Report!$K$3:$K$100000,TRUE)'
            f'-COUNTIFS({no_legacy},Report!$J$3:$J$100000,TRUE,Report!$K$3:$K$100000,TRUE)'
        )
        add_tile(ws, 12, 5, "FULLY MODERN (TLS 1.2/1.3 ONLY)", clean_formula, pct_of_hosts(coord(12, 5)))

        add_tile(ws, 12, 8, "WITH ANY LEGACY PROTOCOL (AT RISK)",
                 "=IFERROR(($B$4-$E$12)/$B$4,0)", '=($B$4-$E$12)&" of "&$B$4&" endpoints"',
                 number_format="0%")

        # SSLv2 / SSLv3 - any support at all is a critical finding
        for coord_ in ("E4", "H4"):
            ws.conditional_formatting.add(
                coord_, CellIsRule(operator="greaterThan", formula=["0"], fill=RED_FILL, font=RED_FONT))
            ws.conditional_formatting.add(
                coord_, CellIsRule(operator="equal", formula=["0"], fill=GREEN_FILL, font=GREEN_FONT))

        # TLS 1.0 / TLS 1.1 - scaled by how widespread it is
        for coord_ in ("B8", "E8"):
            ws.conditional_formatting.add(
                coord_, FormulaRule(formula=[f"AND($B$4>0,{coord_}/$B$4>=0.5)"], fill=RED_FILL, font=RED_FONT, stopIfTrue=True))
            ws.conditional_formatting.add(
                coord_, FormulaRule(formula=[f"AND($B$4>0,{coord_}>0,{coord_}/$B$4<0.5)"], fill=AMBER_FILL, font=AMBER_FONT, stopIfTrue=True))
            ws.conditional_formatting.add(
                coord_, FormulaRule(formula=[f"{coord_}=0"], fill=GREEN_FILL, font=GREEN_FONT, stopIfTrue=True))

        # TLS 1.2 / TLS 1.3 tiles are informational adoption metrics (more is
        # better) - deliberately no red/amber/green severity coloring here.

        ws.conditional_formatting.add(
            "E12", FormulaRule(formula=["IFERROR(E12/$B$4>=0.75,FALSE)"], fill=GREEN_FILL, font=GREEN_FONT, stopIfTrue=True))
        ws.conditional_formatting.add(
            "E12", FormulaRule(formula=["IFERROR(AND(E12/$B$4>=0.4,E12/$B$4<0.75),FALSE)"], fill=AMBER_FILL, font=AMBER_FONT, stopIfTrue=True))
        ws.conditional_formatting.add(
            "E12", FormulaRule(formula=["IFERROR(E12/$B$4<0.4,TRUE)"], fill=RED_FILL, font=RED_FONT, stopIfTrue=True))

        ws.conditional_formatting.add(
            "H12", CellIsRule(operator="greaterThanOrEqual", formula=["0.5"], fill=RED_FILL, font=RED_FONT))
        ws.conditional_formatting.add(
            "H12", FormulaRule(formula=["AND(H12>=0.25,H12<0.5)"], fill=AMBER_FILL, font=AMBER_FONT))
        ws.conditional_formatting.add(
            "H12", CellIsRule(operator="lessThan", formula=["0.25"], fill=GREEN_FILL, font=GREEN_FONT))

        for col, w in {"A": 3, "B": 16, "C": 16, "D": 3, "E": 16, "F": 16,
                        "G": 3, "H": 16, "I": 16}.items():
            ws.column_dimensions[col].width = w

        ws.merge_cells("A16:I16")
        ws["A16"] = "LEGACY PROTOCOLS BY CATEGORY"
        ws["A16"].font = SECTION_FONT
        ws["A16"].border = THIN_BORDER

        breakdown = [
            ("SSLv2 Supported", "=$E$4", RED_BAR),
            ("SSLv3 Supported (POODLE)", "=$H$4", RED_BAR),
            ("TLS 1.0 Supported", "=$B$8", AMBER_BAR),
            ("TLS 1.1 Supported", "=$E$8", AMBER_BAR),
        ]
        for i, (label, formula, _) in enumerate(breakdown):
            r = 18 + i
            ws.cell(row=r, column=2, value=label)
            ws.cell(row=r, column=3, value=formula)

        chart = BarChart()
        chart.type = "bar"
        chart.x_axis.title = "Endpoints Affected"
        chart.y_axis.majorGridlines = None
        chart.legend = None
        cats = Reference(ws, min_col=2, min_row=18, max_row=18 + len(breakdown) - 1)
        vals = Reference(ws, min_col=3, min_row=18, max_row=18 + len(breakdown) - 1)
        chart.add_data(vals, titles_from_data=False)
        chart.set_categories(cats)
        chart.series[0].data_points = [
            DataPoint(idx=i, spPr=GraphicalProperties(solidFill=color))
            for i, (_, _, color) in enumerate(breakdown)
        ]
        ws.add_chart(chart, "E18")

        ws.merge_cells("A35:I35")
        ws["A35"] = "TOP OFFENDERS — HIGHEST-RISK ENDPOINTS (WORK THESE FIRST)"
        ws["A35"].font = SECTION_FONT
        ws["A35"].fill = PatternFill("solid", fgColor="D9D9D9")

        ws.merge_cells("A36:I36")
        ws["A36"] = ("Ranked by Legacy Score = 1000×SSLv2 + 100×SSLv3 + 10×TLS1.0 + 1×TLS1.1 "
                     "(each as 1/0), so any SSLv2 finding always outranks any number of TLS 1.1 "
                     "findings alone. Static snapshot from this scan run (precomputed, not a live "
                     "formula).")
        ws["A36"].font = SUBTEXT_FONT

        headers = ["Rank", "IP Address", "Hostname", "Port", "Scan Date",
                   "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "Legacy Score"]
        for c, h in enumerate(headers, start=1):
            cell = ws.cell(row=37, column=c, value=h)
            cell.font = Font(bold=True)
            cell.border = THIN_BORDER

        top10 = sorted(rows, key=lambda r: r["legacy_score"], reverse=True)[:10]
        for i, r in enumerate(top10):
            row_num = 38 + i
            ws.cell(row=row_num, column=1, value=i + 1)
            ws.cell(row=row_num, column=2, value=r["ip"])
            ws.cell(row=row_num, column=3, value=_neutralize_formula(r["hostname"]) or "(no reverse DNS)")
            ws.cell(row=row_num, column=4, value=r["port"])
            date_val = r["scan_date"]
            try:
                date_val = datetime.strptime(r["scan_date"], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                pass
            c5 = ws.cell(row=row_num, column=5, value=date_val)
            c5.number_format = "yyyy-mm-dd"
            ws.cell(row=row_num, column=6, value=r["sslv2"])
            ws.cell(row=row_num, column=7, value=r["sslv3"])
            ws.cell(row=row_num, column=8, value=r["tls10"])
            ws.cell(row=row_num, column=9, value=r["tls11"])
            ws.cell(row=row_num, column=10, value=r["legacy_score"])

        if top10:
            last = 37 + len(top10)
            for col_letter in ("F", "G"):  # SSLv2, SSLv3 - critical, highlight regardless of rank
                ws.conditional_formatting.add(
                    f"{col_letter}38:{col_letter}{last}",
                    CellIsRule(operator="equal", formula=["TRUE"], fill=RED_FILL, font=Font(color="FFFFFF", bold=True)))
            ws.conditional_formatting.add(
                f"J38:J{last}", ColorScaleRule(
                    start_type="min", start_color="C6EFCE",
                    mid_type="percentile", mid_value=50, mid_color="FFEB9C",
                    end_type="max", end_color="FFC7CE"))
            footnote_row = last + 2
        else:
            footnote_row = 39

        ws.cell(row=footnote_row, column=1,
                value="Full per-endpoint detail (including endpoints beyond the top 10): see Report sheet.")
        ws.cell(row=footnote_row, column=1).font = SUBTEXT_FONT

        # Certificate/cipher findings get their own section appended below
        # everything else, rather than folded into the 3x3 grid above -
        # different risk category (cipher strength / PKI trust) than the
        # protocol-downgrade scoring the grid, chart, and Top Offenders
        # ranking are built around, so it's flagged as its own block instead
        # of implying equal weight by blending in. Appended at the end so
        # the grid/chart/Top Offenders positions above never have to move.
        cert_header_row = footnote_row + 2
        ws.merge_cells(f"A{cert_header_row}:I{cert_header_row}")
        ws[f"A{cert_header_row}"] = ("CERTIFICATE & CIPHER FINDINGS "
                                      "(separate risk category — not part of Legacy Score)")
        ws[f"A{cert_header_row}"].font = SECTION_FONT
        ws[f"A{cert_header_row}"].fill = PatternFill("solid", fgColor="D9D9D9")

        cert_tiles_row = cert_header_row + 2
        add_tile(ws, cert_tiles_row, 2, "SELF-SIGNED CERTS",
                 "=COUNTIF(Report!$R$3:$R$100000,TRUE)", pct_of_hosts(coord(cert_tiles_row, 2)))
        add_tile(ws, cert_tiles_row, 5, "EXPIRED CERTS",
                 "=COUNTIF(Report!$X$3:$X$100000,TRUE)", pct_of_hosts(coord(cert_tiles_row, 5)))
        add_tile(ws, cert_tiles_row, 8, "ENDPOINTS W/ WEAK CIPHERS",
                 '=COUNTIF(Report!$Y$3:$Y$100000,">0")', pct_of_hosts(coord(cert_tiles_row, 8)))

        for coord_ in (coord(cert_tiles_row, 2), coord(cert_tiles_row, 5), coord(cert_tiles_row, 8)):
            ws.conditional_formatting.add(
                coord_, CellIsRule(operator="greaterThan", formula=["0"], fill=RED_FILL, font=RED_FONT))
            ws.conditional_formatting.add(
                coord_, CellIsRule(operator="equal", formula=["0"], fill=GREEN_FILL, font=GREEN_FONT))

        cert_footnote_row = cert_tiles_row + 4
        ws.merge_cells(f"A{cert_footnote_row}:I{cert_footnote_row}")
        ws.cell(row=cert_footnote_row, column=1,
                value=("Certificate/cipher issues are scored separately from protocol downgrade risk - "
                       "not included in Legacy Score or the Top Offenders ranking above. "
                       "Full per-endpoint detail: see Report sheet."))
        ws.cell(row=cert_footnote_row, column=1).font = SUBTEXT_FONT
        return ws

    wb = Workbook()
    wb.remove(wb.active)
    build_overview_sheet(wb)
    build_report_sheet(wb)
    wb.active = 0
    return wb


def write_xlsx(rows: List[dict], xlsx_path: str, logger: logging.Logger) -> None:
    try:
        wb = build_workbook(rows)
    except ImportError:
        logger.warning("openpyxl not installed - skipping .xlsx generation. "
                        "Install with: pip install openpyxl")
        return
    wb.save(xlsx_path)
    logger.info(f"Workbook saved to: {xlsx_path} ({len(rows)} endpoint(s))")


# =============================================================================
# MAIN
# =============================================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized internal SSL/TLS protocol-version assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE)
    parser.add_argument("--host-timeout", type=str, default=DEFAULT_HOST_TIMEOUT,
                         help="nmap --host-timeout per host, so one hung host can't stall a worker")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--output-dir", type=str, default=SCRIPT_DIR)
    parser.add_argument("--masscan-path", type=str, default="masscan")
    parser.add_argument("--nmap-path", type=str, default="nmap")
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--skip-masscan", action="store_true")
    parser.add_argument("--masscan-output-file", type=str, default=None)
    parser.add_argument("--keep-temp", action="store_true",
                         help="keep each host's raw nmap XML under <output-dir>/nmap_xml_<date>/")
    parser.add_argument("--no-xlsx", action="store_true")
    parser.add_argument("--csv-out", type=str, default=None)
    parser.add_argument("--xlsx-out", type=str, default=None)
    parser.add_argument("--from-csv", metavar="FILE",
                         help="skip scanning entirely; rebuild the .xlsx from an existing CSV")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    args.tls_ports = TLS_PORTS

    scan_date = datetime.now().strftime("%Y-%m-%d")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: Could not create output directory '{args.output_dir}': {exc}", file=sys.stderr)
        return 1

    log_path = os.path.join(args.output_dir, f"sslspray_{scan_date}.log")
    csv_path = args.csv_out or os.path.join(args.output_dir, f"sslspray_{scan_date}.csv")
    xlsx_path = args.xlsx_out or os.path.join(args.output_dir, f"sslspray_{scan_date}.xlsx")

    try:
        logger = setup_logging(log_path)
    except OSError as exc:
        print(f"ERROR: Could not open log file '{log_path}': {exc}", file=sys.stderr)
        return 1

    if args.from_csv:
        rows = read_rows_from_csv(args.from_csv)
        if not args.no_xlsx:
            write_xlsx(rows, xlsx_path, logger)
        return 0

    stop_event = threading.Event()

    def handle_sigint(signum, frame):  # noqa: ANN001
        if stop_event.is_set():
            logger.warning("Second interrupt received, forcing exit.")
            sys.exit(130)
        logger.warning("Ctrl+C received - finishing current work and writing "
                        "partial reports. Press Ctrl+C again to force exit.")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    logger.info("=" * 70)
    logger.info("AUTHORIZED SSL/TLS PROTOCOL-VERSION ASSESSMENT")
    logger.info("=" * 70)
    logger.info("Configured subnets in scope:")
    for s in SUBNETS:
        logger.info(f"  - {s}")
    logger.info(f"Configured TLS ports in scope: {', '.join(str(p) for p in TLS_PORTS)}")
    logger.info(f"Workers: {args.workers} | Masscan rate: {args.rate} | "
                f"Host timeout: {args.host_timeout} | Retries: {args.retries}")

    networks = validate_subnets(SUBNETS, logger)
    if not networks:
        logger.error("No valid subnets configured. Exiting.")
        return 1

    masscan_path = check_external_tool(args.masscan_path) or args.masscan_path
    if not args.skip_masscan and check_external_tool(args.masscan_path) is None:
        logger.error(f"Required tool '{args.masscan_path}' was not found on PATH.")
        return 1

    resolved_nmap = check_external_tool(args.nmap_path)
    if resolved_nmap is None:
        logger.error(f"Required tool '{args.nmap_path}' was not found on PATH. "
                      f"There is no fallback for Phase 2 - nmap+NSE (ssl-enum-ciphers, "
                      f"sslv2) is the only protocol-enumeration engine this script has.")
        return 1
    args.nmap_path = resolved_nmap

    raw_records: List[Tuple[str, int, str]] = []
    if args.skip_masscan:
        if not args.masscan_output_file or not os.path.exists(args.masscan_output_file):
            logger.error("--skip-masscan requires a valid --masscan-output-file.")
            return 1
        raw_records, _ = parse_masscan_list_output(args.masscan_output_file, 0)
    else:
        masscan_out = args.masscan_output_file or os.path.join(
            args.output_dir, f".masscan_output_{scan_date}.txt")
        try:
            raw_records = run_masscan_phase1(masscan_path, SUBNETS, args.rate, masscan_out,
                                              args.interface, TLS_PORTS, logger, stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Phase 1 discovery failed unexpectedly: {exc}")
            raw_records = []

    port_set = set(TLS_PORTS)
    ports_by_ip: Dict[str, set] = {}
    for ip, port, _proto in raw_records:
        if port not in port_set:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Skipping malformed IP address from scan output: {ip}")
            continue
        ports_by_ip.setdefault(ip, set()).add(port)

    logger.info(f"Discovered {len(ports_by_ip)} unique host(s) with a TLS port open after deduplication.")

    hosts: List[DiscoveredHost] = []
    for ip, ports in ports_by_ip.items():
        if stop_event.is_set():
            break
        hostname = resolve_hostname(ip, timeout=2.0)
        subnet = subnet_for_ip(ip, networks)
        hosts.append(DiscoveredHost(ip=ip, hostname=hostname, subnet=subnet, ports=sorted(ports)))

    rows: List[dict] = []
    if hosts:
        # Deliberately not gated on "and not stop_event.is_set()" - Ctrl+C
        # during the hostname-resolution loop above can set stop_event
        # while hosts is already non-empty, and run_phase2() itself already
        # honors stop_event correctly (cancels remaining futures, returns
        # whatever completed). Gating here too meant those already-resolved
        # hosts were silently dropped and Phase 2 never ran at all, so a
        # scan interrupted at exactly that point wrote an empty report -
        # contradicting the SIGINT handler's own "finishing current work
        # and writing partial reports" message.
        rows = run_phase2(hosts, args, logger, stop_event)
    else:
        logger.info("No hosts with a TLS port open discovered; skipping Phase 2 audit.")

    write_csv(rows, csv_path, logger)
    if not args.no_xlsx:
        write_xlsx(rows, xlsx_path, logger)

    legacy = sum(1 for r in rows if r["legacy_count"] > 0)
    logger.info("=" * 70)
    logger.info("SCAN SUMMARY")
    logger.info(f"  TLS endpoints confirmed: {len(rows)} | With at least one legacy protocol: {legacy}")
    logger.info("=" * 70)
    logger.info(f"Reports written to: {os.path.abspath(args.output_dir)}")

    if stop_event.is_set():
        logger.warning("Scan was interrupted by user; reports reflect partial results.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
