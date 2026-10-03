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
| 4 | The Cyber Kill Chain | WannaCry mapped to Kill Chain stages and ATT&CK TTPs | ⏳ |
| 5 | Threat Hunting Concept | Hypothesis-driven hunt (Splunk/ELK) | ⏳ |
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
└── week3-data-processing/
    ├── DEPLOYMENT.md          MISP Docker deployment
    ├── data/                  raw → normalized IOCs, MISP JSON event
    ├── scripts/               normalize_iocs.py, push_to_misp.py, sigma_to_elastic.py
    ├── sigma/                 detection rule
    └── images/                screenshots
```

## Quick start (Week 3 scripts)

```bash
cd week3-data-processing
pip install -r requirements.txt
python3 scripts/normalize_iocs.py          # raw → clean CSV
python3 scripts/push_to_misp.py --offline  # build MISP JSON (or push to MISP with MISP_URL/MISP_KEY)
python3 scripts/sigma_to_elastic.py        # Sigma → Elastic query
```
