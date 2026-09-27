#!/usr/bin/env python3
"""
normalize_iocs.py - Week 3: filtering and normalization of collected IOCs.

Reads the raw, messy IOC list collected in Week 2 (data/raw_iocs.txt) and
produces a clean, typed, de-duplicated dataset ready for MISP import.

Pipeline:
  1. Parse      - split indicator / source / key=value annotations, skip comments
  2. Refang     - hxxp -> http, [.] -> ., strip URL scheme and path
  3. Classify   - detect the MISP attribute type with regular expressions
  4. Validate   - reject malformed values (e.g. a hash with the wrong length)
  5. Normalize  - lower-case where the type is case-insensitive
                  (hashes, domains, CVE ids are upper-cased) but NEVER
                  Bitcoin addresses, which are case-sensitive (Base58)
  6. Filter     - drop known-benign values (a small local "warninglist")
  7. Deduplicate- same (type, value) keeps one row and merges the sources
  8. Enrich     - MISP category, to_ids flag, comment, file-object grouping

Only the Python standard library is used.

Usage:
    python3 scripts/normalize_iocs.py
    python3 scripts/normalize_iocs.py -i data/raw_iocs.txt -o data/normalized_iocs.csv
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

# --- 3. Type detection (order matters: most specific first) -----------------
PATTERNS = [
    ("sha256",        re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("sha1",          re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("md5",           re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("vulnerability", re.compile(r"^cve-\d{4}-\d{4,}$", re.I)),
    ("btc",           re.compile(r"^(bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")),
    ("ip-dst",        re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")),
    ("domain",        re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)),
]
HEXLIKE = re.compile(r"^[a-f0-9]{20,}$", re.I)  # looks like a hash but wrong length

# MISP category + default to_ids per type (matches MISP describeTypes defaults)
MISP_META = {
    "sha256":        ("Payload delivery",   True),
    "sha1":          ("Payload delivery",   True),
    "md5":           ("Payload delivery",   True),
    "domain":        ("Network activity",   True),
    "ip-dst":        ("Network activity",   True),
    "btc":           ("Financial fraud",    True),
    "vulnerability": ("External analysis",  False),
    "mutex":         ("Artifacts dropped",  True),
}

# --- 6. Local allowlist (simplified version of MISP warninglists) ----------
BENIGN_DOMAINS = {"microsoft.com", "windows.com", "windowsupdate.com", "google.com",
                  "msftncsi.com", "digicert.com"}
BENIGN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"}


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"^hxxps?://", "", v, flags=re.I)
    v = re.sub(r"^https?://", "", v, flags=re.I)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    v = v.split("/")[0]                      # drop URL path
    if v.lower().startswith("www."):         # www.<domain> -> <domain>
        v = v[4:]
    return v


def classify(value: str):
    if value.lower().startswith("mutex:"):
        return "mutex", value.split(":", 1)[1].strip()
    for t, rx in PATTERNS:
        if rx.match(value):
            return t, value
    return None, value


def normalize_value(t: str, v: str) -> str:
    if t in ("sha256", "sha1", "md5", "domain", "ip-dst"):
        return v.lower()
    if t == "vulnerability":
        return v.upper()
    return v  # btc, mutex: case-sensitive -> unchanged


def is_benign(t: str, v: str) -> bool:
    if t == "ip-dst":
        return v in BENIGN_IPS
    if t == "domain":
        return any(v == d or v.endswith("." + d) for d in BENIGN_DOMAINS)
    return False


def parse_line(line: str):
    if "#" in line:
        ind, _, note = line.partition("#")
    else:
        ind, note = line, ""
    source, meta = note.strip(), {}
    if "|" in note:
        source, _, kv = note.partition("|")
        for pair in kv.split():
            if "=" in pair:
                k, _, val = pair.partition("=")
                meta[k.strip()] = val.strip()
    return ind.strip(), source.strip(), meta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input", default=BASE / "data" / "raw_iocs.txt")
    ap.add_argument("-o", "--output", default=BASE / "data" / "normalized_iocs.csv")
    ap.add_argument("-r", "--report", default=BASE / "data" / "processing_report.json")
    args = ap.parse_args()

    stats = Counter()
    rejected, filtered = [], []
    clean = OrderedDict()  # (type, value) -> row

    for n, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stats["raw_lines"] += 1
        indicator, source, meta = parse_line(line)
        t, v = classify(refang(indicator))

        if t is None:
            reason = "hash-like value with invalid length" if HEXLIKE.match(v) else "unknown indicator type"
            rejected.append({"line": n, "value": indicator, "reason": reason})
            stats["rejected"] += 1
            continue

        v = normalize_value(t, v)
        if v != indicator:
            stats["modified_by_normalization"] += 1

        # .onion is a Tor hidden service, not a public DNS domain
        is_onion = t == "domain" and v.endswith(".onion")

        if is_benign(t, v):
            filtered.append({"line": n, "type": t, "value": v, "reason": "known benign (allowlist)"})
            stats["filtered_benign"] += 1
            continue

        key = (t, v)
        if key in clean:
            stats["duplicates_merged"] += 1
            if source and source not in clean[key]["source"]:
                clean[key]["source"] += "; " + source
            continue

        category, to_ids = MISP_META[t]
        comment = ""
        if meta.get("role") == "killswitch":
            # Blocking the kill-switch domain would make WannaCry run!
            to_ids = False
            comment = "WannaCry kill-switch domain (sinkholed). DO NOT BLOCK: blocking re-enables encryption. Monitor DNS lookups instead."
        elif is_onion:
            comment = "Tor hidden-service C2 (reachable only via Tor)"
        elif t == "btc":
            comment = "Hard-coded ransom wallet"
        elif t == "vulnerability":
            comment = {"CVE-2017-0144": "SMBv1 remote code execution (MS17-010) - exploited by EternalBlue",
                       "CVE-2017-0147": "SMBv1 information disclosure (MS17-010)"}.get(v, "")
        elif t == "mutex":
            comment = "WannaCry mutex"
        elif meta.get("file"):
            comment = f"WannaCry component {meta['file']}"

        clean[key] = {
            "type": t, "category": category, "value": v,
            "to_ids": str(to_ids).lower(), "comment": comment,
            "object": f"file:{meta['file']}" if meta.get("file") and t in ("md5", "sha1", "sha256") else "",
            "source": source,
        }

    rows = list(clean.values())
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["type", "category", "value", "to_ids", "comment", "object", "source"])
        w.writeheader()
        w.writerows(rows)

    stats["clean_iocs"] = len(rows)
    report = {
        "input": str(Path(args.input).name),
        "output": str(Path(args.output).name),
        "statistics": dict(stats),
        "by_type": dict(Counter(r["type"] for r in rows)),
        "rejected": rejected,
        "filtered": filtered,
    }
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    # --- console summary (screenshot this for the report) ---
    print("=" * 60)
    print(" IOC NORMALIZATION REPORT - WannaCry / Lazarus Group")
    print("=" * 60)
    print(f" Raw indicator lines        : {stats['raw_lines']}")
    print(f" Rejected (malformed)       : {stats['rejected']}")
    print(f" Filtered (benign allowlist): {stats['filtered_benign']}")
    print(f" Duplicates merged          : {stats['duplicates_merged']}")
    print(f" Values changed by normalize: {stats['modified_by_normalization']}")
    print(f" CLEAN IOCs written         : {len(rows)}")
    print("-" * 60)
    for t, c in sorted(report["by_type"].items()):
        print(f"   {t:<14} {c}")
    print("-" * 60)
    for r in rejected:
        print(f" [REJECTED] line {r['line']}: {r['value'][:40]}... -> {r['reason']}")
    for f in filtered:
        print(f" [FILTERED] line {f['line']}: {f['value']} -> {f['reason']}")
    print(f"\n Output: {args.output}\n Report: {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
