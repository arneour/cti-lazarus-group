"""Bulk-load the downloaded datasets into Elasticsearch (no extra packages).

Each dataset goes into its own index: hunt-otrf-<name>.
Field names are kept exactly as in the original Windows/Sysmon events
(Image, CommandLine, ParentImage, ScriptBlockText, ServiceName, ...),
so the queries in ../hunts/ work without any ECS mapping.

Usage:  python load_to_elastic.py [http://localhost:9200]
"""
import json
import pathlib
import sys
import urllib.request

ES = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9200"
DATA = pathlib.Path(__file__).parent / "data"


def call(method, path, body=None, ndjson=False):
    data = None
    headers = {}
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
    req = urllib.request.Request(ES + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read() or b"{}")


# All strings as keyword (exact match + aggregations + ES|QL).
# Keywords/Task are int in some events and str in others -> force keyword.
template = {
    "index_patterns": ["hunt-otrf-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "date_detection": False,
            "numeric_detection": False,
            "dynamic_templates": [
                {"strings": {"match_mapping_type": "string",
                             "mapping": {"type": "keyword", "ignore_above": 32766}}}
            ],
            "properties": {
                "@timestamp": {"type": "date"},
                "EventID": {"type": "long"},
                "Keywords": {"type": "keyword"},
                "Task": {"type": "keyword"},
                "dataset": {"type": "keyword"},
            },
        },
    },
}
call("PUT", "/_index_template/hunt-otrf", template)
print("[+] index template hunt-otrf created")

for f in sorted(DATA.glob("*.json")):
    name = f.stem
    index = f"hunt-otrf-{name}"
    try:
        call("DELETE", f"/{index}")
    except Exception:
        pass
    lines, total = [], 0
    for raw in f.open(encoding="utf-8", errors="replace"):
        raw = raw.strip()
        if not raw:
            continue
        doc = json.loads(raw)
        doc["dataset"] = name
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc))
        if len(lines) >= 2000:
            res = call("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True)
            total += len(lines) // 2
            if res.get("errors"):
                print("    some documents failed, first error:",
                      next(i for i in res["items"] if "error" in i["index"])["index"]["error"])
            lines = []
    if lines:
        call("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True)
        total += len(lines) // 2
    call("POST", f"/{index}/_refresh")
    count = call("GET", f"/{index}/_count")["count"]
    print(f"[+] {index}: sent {total}, indexed {count}")

print("\nNext: Kibana -> Discover -> switch to ES|QL and run the queries from ../hunts/")
