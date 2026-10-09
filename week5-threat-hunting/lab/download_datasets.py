"""Download the three OTRF Security-Datasets recordings used in week 5.

Security-Datasets (formerly Mordor) are public Windows event logs recorded
while known adversary techniques were simulated in a lab. They are made for
practising detection and hunting.

Usage:  python download_datasets.py        (writes to ./data/)
"""
import io
import pathlib
import urllib.request
import zipfile

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
DATASETS = {
    # name in our index        : path inside the Security-Datasets repo
    "empire_launcher_vbs": "execution/host/empire_launcher_vbs.zip",
    "empire_psexec_svcctl": "lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
    "ntds_volume_shadow_copy": "credential_access/host/cmd_dumping_ntds_dit_file_volume_shadow_copy.zip",
}

out = pathlib.Path(__file__).parent / "data"
out.mkdir(exist_ok=True)

for name, path in DATASETS.items():
    print(f"[*] {name}: downloading {path}")
    raw = urllib.request.urlopen(BASE + path, timeout=120).read()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        member = next(m for m in z.namelist() if m.endswith(".json"))
        target = out / f"{name}.json"
        target.write_bytes(z.read(member))
    print(f"    saved {target} ({target.stat().st_size // 1024} KB)")

print("[+] done")
