#!/usr/bin/env python3
"""
push_to_misp.py - Week 3: import the normalized WannaCry IOCs into MISP.

Reads data/normalized_iocs.csv (produced by normalize_iocs.py) and creates
one MISP event with:
  * event-level context: TLP, threat level, analysis state, and galaxy clusters
    (Lazarus Group threat actor, WannaCry ransomware, MITRE ATT&CK techniques)
  * MISP "file" objects that group the MD5/SHA1/SHA256 of the same file
  * standalone attributes (domains, .onion C2, BTC wallets, CVEs, mutex)
  * a MISP warninglist check before upload (filters false positives)

Two modes:
  --offline   build the event locally and save it as MISP JSON
              (data/wannacry_misp_event.json). It can be imported in the MISP UI:
              Event Actions -> Import from... -> MISP standard (JSON)
  (default)   push the event to a running MISP instance through the REST API

Requirements:  pip install pymisp

Examples:
  python3 scripts/push_to_misp.py --offline
  export MISP_URL=https://localhost  MISP_KEY=<your API key>
  python3 scripts/push_to_misp.py --insecure
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    from pymisp import MISPEvent, MISPObject, PyMISP
except ImportError:
    sys.exit("PyMISP is missing: pip install pymisp")

BASE = Path(__file__).resolve().parent.parent

EVENT_INFO = "WannaCry ransomware (Lazarus Group) - OSINT IOC collection [CTI course project]"

EVENT_TAGS = [
    "tlp:clear",                                    # TLP 2.0 (formerly tlp:white)
    'misp-galaxy:threat-actor="Lazarus Group"',
    'misp-galaxy:mitre-intrusion-set="Lazarus Group - G0032"',
    'misp-galaxy:ransomware="WannaCry"',
    'misp-galaxy:mitre-malware="WannaCry - S0366"',
    # ATT&CK techniques documented for WannaCry (MITRE S0366)
    'misp-galaxy:mitre-attack-pattern="Exploitation of Remote Services - T1210"',
    'misp-galaxy:mitre-attack-pattern="Data Encrypted for Impact - T1486"',
    'misp-galaxy:mitre-attack-pattern="Inhibit System Recovery - T1490"',
    'misp-galaxy:mitre-attack-pattern="Multi-hop Proxy - T1090.003"',
    'misp-galaxy:mitre-attack-pattern="Windows Service - T1543.003"',
    'misp-galaxy:mitre-attack-pattern="Windows Permissions - T1222.001"',
    'misp-galaxy:mitre-attack-pattern="Hidden Files and Directories - T1564.001"',
]


def load_rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def build_event(rows):
    ev = MISPEvent()
    ev.info = EVENT_INFO
    ev.date = "2017-05-12"          # start of the WannaCry outbreak
    ev.threat_level_id = 1          # 1 = High
    ev.analysis = 2                 # 2 = Completed
    ev.distribution = 0             # 0 = Your organisation only
    for t in EVENT_TAGS:
        ev.add_tag(t)

    # 1) group hashes that belong to the same file into one MISP "file" object
    files = defaultdict(list)
    for r in rows:
        if r["object"].startswith("file:"):
            files[r["object"][5:]].append(r)
    for filename, attrs in files.items():
        obj = MISPObject("file")
        obj.comment = f"WannaCry component {filename}"
        obj.add_attribute("filename", value=filename, to_ids=False)
        for a in attrs:
            obj.add_attribute(a["type"], value=a["value"], to_ids=a["to_ids"] == "true",
                              comment=f"source: {a['source']}")
        ev.add_object(obj)

    # 2) everything else as standalone attributes
    for r in rows:
        if r["object"]:
            continue
        attr = ev.add_attribute(r["type"], r["value"], category=r["category"],
                                to_ids=r["to_ids"] == "true",
                                comment=(r["comment"] + f" | source: {r['source']}").strip(" |"))
        if "kill-switch" in r["comment"]:
            attr.add_tag("kill-switch")
        if r["value"].endswith(".onion"):
            attr.add_tag("tor:c2")
    return ev


def warninglist_check(misp, rows):
    """Ask MISP whether any value hits a warninglist (known benign / false positive)."""
    values = [r["value"] for r in rows]
    hits = misp.values_in_warninglist(values) or {}
    if not isinstance(hits, dict):   # MISP returns [] when nothing matches
        hits = {}
    if hits:
        print("[!] Warninglist hits (review before sharing):")
        for value, lists in hits.items():
            names = ", ".join(w.get("name", "?") for w in lists)
            print(f"    {value} -> {names}")
    else:
        print("[+] No warninglist hits - no known false positives in the dataset")
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--input", default=BASE / "data" / "normalized_iocs.csv")
    ap.add_argument("--offline", action="store_true", help="only write MISP JSON, do not contact MISP")
    ap.add_argument("-o", "--output", default=BASE / "data" / "wannacry_misp_event.json")
    ap.add_argument("--url", default=os.getenv("MISP_URL", "https://localhost"))
    ap.add_argument("--key", default=os.getenv("MISP_KEY"))
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed lab cert)")
    ap.add_argument("--publish", action="store_true", help="publish the event after creation")
    args = ap.parse_args()

    rows = load_rows(args.input)
    event = build_event(rows)
    n_obj = len(event.objects)
    n_attr = len(event.attributes) + sum(len(o.attributes) for o in event.objects)
    print(f"[+] Built event: {n_attr} attributes ({len(event.attributes)} standalone, "
          f"{n_obj} file objects), {len(event.tags)} tags")

    # wrap in {"Event": ...} - the format expected by MISP's "Import from... MISP JSON"
    Path(args.output).write_text(json.dumps({"Event": json.loads(event.to_json())}, indent=2),
                                 encoding="utf-8")
    print(f"[+] MISP JSON saved to {args.output}")
    if args.offline:
        return 0

    if not args.key:
        sys.exit("[-] Set MISP_KEY (Administration -> List Auth Keys -> Add authentication key)")
    misp = PyMISP(args.url, args.key, ssl=not args.insecure)
    warninglist_check(misp, rows)

    created = misp.add_event(event, pythonify=True)
    if isinstance(created, dict) and created.get("errors"):
        sys.exit(f"[-] MISP error: {created['errors']}")
    print(f"[+] Event created: id={created.id} uuid={created.uuid}")
    print(f"    Open: {args.url.rstrip('/')}/events/view/{created.id}")
    if args.publish:
        misp.publish(created)
        print("[+] Event published")
    return 0


if __name__ == "__main__":
    sys.exit(main())
