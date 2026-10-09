# Cyber Threat Intelligence Project — Lazarus Group

**Course:** Introduction to Threat Hunting (2026–2027)
**Group topic:** Lazarus Group — North Korean state-sponsored APT (MITRE ATT&CK [G0032](https://attack.mitre.org/groups/G0032/))
**Case study:** WannaCry ransomware, May 2017 (MITRE ATT&CK [S0366](https://attack.mitre.org/software/S0366/))

| Member |  |
|---|---|
| Arnur Seidilla |
| Mukamet Valihan | 
| Nurkhat Zholseit |

> All data in this repository comes from **public, open sources** (TLP:CLEAR).
> No malware samples are stored here, and no third-party hosts were scanned or contacted.

## Weekly progress

| Week | Syllabus topic | Deliverables | Status |
|---|---|---|---|
| 1 | CTI Fundamentals | [Glossary of 25 CTI terms, Lazarus operations timeline, threat classification by actor / type / source](week1-fundamentals/README.md) | ✅ |
| 2 | Data Collection Process | [OSINT with VirusTotal, Maltego, Shodan; data source mapping (Admiralty code)](week2-data-collection/README.md) | ✅ |
| 3 | Data Processing and Exploitation | [MISP on Docker, normalization script, IOC import via PyMISP, galaxies, correlation, Sigma rule](week3-data-processing/README.md) | ✅ |
| 4 | The Cyber Kill Chain | [WannaCry mapped to the 7 Kill Chain stages and ATT&CK v19 TTPs, Courses of Action matrix, ATT&CK Navigator layer](week4-kill-chain/README.md) | ✅ |
| 5 | Threat Hunting Concept | [ELK lab on OTRF Security-Datasets: hypothesis-driven hunt (PowerShell) and intel-driven hunt (WannaCry TTPs) in ES\|QL, Sigma rule](week5-threat-hunting/README.md) | ✅ |
| 6 | ATT&CK Framework | Technique deep-dive | ⏳ |
| 7 | MITRE CAR | Analytics for Lazarus techniques | ⏳ |
| 8 | Adversary emulation plan | Lazarus emulation plan | ⏳ |
| 9 | Atomic Red Team | Atomic tests for mapped techniques | ⏳ |
| 10 | APT techniques | Final analysis | ⏳ |

## Repository structure

```
cti-lazarus-group/
├── week1-fundamentals/        glossary, threat classification
├── week2-data-collection/     OSINT results + screenshots
├── week3-data-processing/
│   ├── DEPLOYMENT.md          MISP Docker deployment
│   ├── data/                  raw → normalized IOCs, MISP JSON event
│   ├── scripts/               normalize_iocs.py, push_to_misp.py, sigma_to_elastic.py
│   ├── sigma/                 detection rule
│   └── images/                screenshots
├── week4-kill-chain/
│   ├── wannacry-attack-layer.json   ATT&CK Navigator layer
│   └── images/                Navigator export (SVG)
└── week5-threat-hunting/
    ├── lab/                   docker-compose (ELK), dataset download + loader, run_lab.bat
    ├── hunts/                 H1/H2 ES|QL queries, hunt_offline.py
    ├── results/               hunt output
    ├── sigma/                 detection rule from H1
    └── images/                Kibana screenshots
```

## Quick start (Week 3 scripts)

```bash
cd week3-data-processing
pip install -r requirements.txt
python3 scripts/normalize_iocs.py          # raw → clean CSV
python3 scripts/push_to_misp.py --offline  # build MISP JSON (or push to MISP with MISP_URL/MISP_KEY)
python3 scripts/sigma_to_elastic.py        # Sigma → Elastic query
```

## Quick start (Week 5 hunting lab)

```bash
cd week5-threat-hunting/lab
docker compose up -d                 # Elasticsearch + Kibana (Windows: just run run_lab.bat)
python download_datasets.py          # OTRF Security-Datasets
python load_to_elastic.py            # indices hunt-otrf-*
# Kibana http://localhost:5601 -> Discover -> ES|QL, queries in ../hunts/
python ../hunts/hunt_offline.py      # same hunts without ELK
```
