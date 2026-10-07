# Week 4 — The Cyber Kill Chain: WannaCry (Lazarus Group, 2017)

## Objective
Analyze a real-world cyberattack through the seven stages of the Lockheed
Martin Cyber Kill Chain, map every stage to MITRE ATT&CK tactics and
techniques, and identify where a defender could have broken the chain.

**Case:** WannaCry ransomware worm, 12 May 2017. It continues the case study
from weeks 2–3: the hashes, the kill-switch domain and the MISP event built
there are reused here. Attribution to Lazarus Group (G0032) was made publicly
by the US and UK governments (December 2017) and in the US DOJ complaint
against Park Jin Hyok (September 2018).

---

## 1. The model in one paragraph

Hutchins, Cloppert and Amin (Lockheed Martin, 2011) described an intrusion
as a chain of seven dependent stages. The adversary has to complete **every**
stage to reach the objective; the defender only has to break **one**. The paper
calls this *intelligence-driven defense*: analyze each campaign, find the
indicators of each stage, and push detection as early in the chain as
possible. The model also gives a **Courses of Action matrix**: for each stage,
what can be done to *Detect, Deny, Disrupt, Degrade, Deceive* or *Destroy*.

| # | Stage | Question it answers |
|---|---|---|
| 1 | Reconnaissance | How did the adversary choose and study the target? |
| 2 | Weaponization | What deliverable payload was built (exploit + backdoor)? |
| 3 | Delivery | How did the payload reach the victim? |
| 4 | Exploitation | What vulnerability triggered code execution? |
| 5 | Installation | How did the malware persist on the host? |
| 6 | Command & Control (C2) | How did the malware talk back to the operator? |
| 7 | Actions on Objectives | What was the actual goal? |

---

## 2. Attack timeline (12 May 2017, UTC)

| Time | Event |
|---|---|
| 14 Mar 2017 | Microsoft releases **MS17-010**, patching CVE-2017-0143…0148 in SMBv1 |
| 14 Apr 2017 | Shadow Brokers leak NSA tools incl. **EternalBlue** and **DoublePulsar** |
| 12 May ~07:44 | First WannaCry infections observed; spread is automatic, no phishing |
| 12 May afternoon | NHS England, Telefónica, Renault, Deutsche Bahn and others report outages |
| 12 May, afternoon | Researcher Marcus Hutchins registers the kill-switch domain; new infections stop executing the payload |
| 12–13 May | Microsoft releases emergency patches for unsupported Windows XP / Server 2003 |
| Result | 200,000+ computers in 150+ countries (Europol); ransom paid was small (~$140k in BTC) compared to the damage |

---

## 3. Kill Chain → ATT&CK mapping

ATT&CK version used: **Enterprise v19** (April 2026). Note that v19 split the
old *Defense Evasion* tactic into **Stealth (TA0005)** and **Defense
Impairment (TA0112)**; the tables below already use the new names.

Techniques marked ✅ are listed in the MITRE ATT&CK entry for WannaCry
(S0366). Techniques marked ◻ are our own analytical mapping based on public
malware analyses; they are not in S0366.

### Stage 1 — Reconnaissance
WannaCry did **no targeted reconnaissance**. It was opportunistic: the worm
scanned the internet and the local subnet for anything with TCP/445 open.
Reconnaissance was automated and folded into propagation.

| Activity | Tactic | Technique | |
|---|---|---|---|
| Scans random public IPv4 addresses on TCP/445 | Reconnaissance | T1595.001 Active Scanning: Scanning IP Blocks | ◻ |
| Determines its own subnet to scan neighbours | Discovery | T1016 System Network Configuration Discovery | ✅ |
| Scans local segment for exploitable hosts | Discovery | T1018 Remote System Discovery | ✅ |

### Stage 2 — Weaponization
The authors combined a leaked nation-state exploit with their own ransomware
code into a single self-propagating binary.

| Activity | Tactic | Technique | |
|---|---|---|---|
| Reused leaked EternalBlue exploit and DoublePulsar implant | Resource Development | T1588.005 Obtain Capabilities: Exploits | ◻ |
| Built the worm (`mssecsvc.exe`) with the encryptor (`tasksche.exe`) embedded as a resource | Resource Development | T1587.001 Develop Capabilities: Malware | ◻ |

### Stage 3 — Delivery
Initial infection came from **direct SMB connections to internet-exposed
port 445**. Early media reports about phishing e-mails were not confirmed by
any vendor analysis.

| Activity | Tactic | Technique | |
|---|---|---|---|
| SMBv1 packets sent to exposed TCP/445 on the internet | Initial Access | T1190 Exploit Public-Facing Application | ◻ |
| Worm copies its payload to a newly compromised host | Lateral Movement | T1570 Lateral Tool Transfer | ✅ |

### Stage 4 — Exploitation
| Activity | Tactic | Technique | |
|---|---|---|---|
| EternalBlue (**CVE-2017-0144**) buffer overflow in `srv.sys` → kernel code execution; DoublePulsar is installed or reused, then injects the payload DLL into `lsass.exe` | Lateral Movement | T1210 Exploitation of Remote Services | ✅ |
| Enumerates RDP sessions and runs the decryptor in each (`taskse.exe`) | Lateral Movement | T1563.002 RDP Hijacking | ✅ |

### Stage 5 — Installation
| Activity | Tactic | Technique | |
|---|---|---|---|
| Creates service **`mssecsvc2.0`** ("Microsoft Security Center (2.0) Service"), binary `C:\Windows\mssecsvc.exe -m security` | Persistence / Privilege Escalation | T1543.003 Windows Service | ✅ |
| Drops `tasksche.exe` and unpacks working files into a hidden folder under `C:\ProgramData\` | Stealth | T1564.001 Hidden Files and Directories (`attrib +h .`) | ✅ |
| Grants Everyone full access to its folder (`icacls . /grant Everyone:F /T /C /Q`) | Defense Impairment | T1222.001 Windows File and Directory Permissions Modification | ✅ |
| Adds a `Run` key so the decryptor window comes back after reboot | Persistence | T1547.001 Registry Run Keys | ◻ |

### Stage 6 — Command & Control
| Activity | Tactic | Technique | |
|---|---|---|---|
| Bundled Tor client (`taskhsvc.exe`) connects to `.onion` C2 servers | Command and Control | T1090.003 Multi-hop Proxy | ✅ |
| Custom encrypted protocol over Tor | Command and Control | T1573.002 Asymmetric Cryptography | ✅ |
| **Kill-switch check**: HTTP GET to `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`. If it answers, the worm exits | Command and Control | T1071.001 Web Protocols | ◻ |

The kill-switch is not real C2, but it is the most important network
indicator of the whole campaign: it is why the outbreak stopped.

### Stage 7 — Actions on Objectives
| Activity | Tactic | Technique | |
|---|---|---|---|
| Finds user files by extension (176 types) and removable/mapped drives | Discovery | T1083 File and Directory Discovery; T1120 Peripheral Device Discovery | ✅ |
| Kills SQL Server, Exchange and MySQL processes to unlock databases | Impact | T1489 Service Stop | ✅ |
| Encrypts files (AES-128 per file, keys wrapped with RSA-2048), `.WNCRY` extension, $300→$600 BTC ransom | Impact | T1486 Data Encrypted for Impact | ✅ |
| `vssadmin delete shadows /all /quiet`, `wbadmin delete catalog -quiet`, `bcdedit … recoveryenabled no` | Impact | T1490 Inhibit System Recovery | ✅ |
| `wmic shadowcopy delete` | Execution | T1047 Windows Management Instrumentation | ✅ |
| Spreads to the next host and the chain restarts from Stage 3 | Lateral Movement | T1210, T1570 | ✅ |

A second, often-cited objective is **disruption**: the decryptor could not
reliably match payments to victims, so the design looks closer to sabotage
than to a profit-optimized ransomware business. This fits Lazarus's history
from week 1 (Sony 2014 wiper, false-flag personas).

The full mapping is exported as an ATT&CK Navigator layer:
[`wannacry-attack-layer.json`](wannacry-attack-layer.json)
(open <https://mitre-attack.github.io/attack-navigator/> → *Open Existing
Layer* → *Upload from local*).

![ATT&CK Navigator layer](images/navigator-layer.png)

---

## 4. Courses of Action matrix

Where a defender in May 2017 could have broken the chain:

| Stage | Detect | Deny | Disrupt | Degrade | Deceive |
|---|---|---|---|---|---|
| Recon | IDS: inbound SMB scans from internet | Block TCP/445 at the perimeter | — | — | Honeypot on 445 (logs the exploit) |
| Weaponization | CTI on Shadow Brokers leak (April) | — | — | — | — |
| Delivery | NetFlow: SMB from internet | Firewall: no 445 inbound; disable **SMBv1** | IPS signature for EternalBlue | Network segmentation | — |
| Exploitation | IDS: ETERNALBLUE / DoublePulsar signatures | **Apply MS17-010** (available 2 months before) | EDR blocks kernel shellcode | — | — |
| Installation | Sysmon/7045: new service `mssecsvc2.0` | Application allow-listing (AppLocker) | EDR quarantine | Least privilege | — |
| C2 | DNS: kill-switch query; Tor traffic | Block Tor at egress | — | — | **Sinkhole the kill-switch domain** (what actually stopped it) |
| Actions | `vssadmin delete shadows` alert; mass file renames | Offline backups | Isolate host | Controlled Folder Access | Canary files |

**Key lesson:** WannaCry was preventable at stages 3–4 by two controls that
already existed: disable SMBv1 / close 445 at the perimeter, and patch
MS17-010. And it was stopped at stage 6 by a *deception-like* action
(registering the domain the malware checked), not by any security product.

---

## 5. Kill Chain vs MITRE ATT&CK

| | Lockheed Martin Kill Chain | MITRE ATT&CK |
|---|---|---|
| Purpose | Strategic model of an intrusion; plan defense per stage | Knowledge base of real adversary behavior |
| Granularity | 7 stages | 15 Enterprise tactics in v19 (Stealth and Defense Impairment replaced Defense Evasion), 200+ techniques, sub-techniques, procedures |
| Order | Strictly linear | Tactics are not ordered; any tactic can repeat |
| Focus | Perimeter and malware delivery | Post-compromise behavior inside the network |
| Coverage of insiders / cloud / lateral movement | Weak | Strong (separate matrices for Enterprise, Mobile, ICS) |
| Best use | Explaining a campaign, choosing controls, CoA | Detection engineering, threat hunting, gap analysis |

**Limitations we saw on WannaCry:**
- The chain is **linear**, but a worm is a **loop**: every new victim restarts
  the chain at Delivery from *inside* the network.
- Reconnaissance and Weaponization happen on the adversary's side, so they are
  almost invisible to the defender (we only know them from the leak timeline).
- Most of the useful detail (service names, `icacls`, `vssadmin`) sits in
  stages 5–7, which the Kill Chain treats as just three boxes. ATT&CK splits
  them into a dozen techniques we can hunt for.

The **Unified Kill Chain** (Pols, 2017, updated 2022) combines both: 18 phases
grouped into *In → Through → Out*, which fits worms and lateral movement
better.

---

## 6. From mapping to hunting (link to Week 5)

Pyramid of Pain view of our indicators:

| Level | WannaCry indicator | Stage |
|---|---|---|
| Hash | `24d004a1…1022c` (mssecsvc.exe), `ed01ebfb…41aa` (tasksche.exe) | 5 |
| Domain | kill-switch domain | 6 |
| Network artifact | burst of outbound TCP/445 to many hosts | 1, 3 |
| Host artifact | service `mssecsvc2.0`, `-m security` argument | 5 |
| Tool | Tor client `taskhsvc.exe` | 6 |
| **TTP** | shadow copy deletion, permission change, service install | 5, 7 |

Hashes are trivial to change; TTPs are not. In week 5 we turn the bottom and
the top of this pyramid into **intel-driven** and **hypothesis-driven** hunts
in ELK.

---

## Sources
- E. Hutchins, M. Cloppert, R. Amin — *Intelligence-Driven Computer Network
  Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill
  Chains*, Lockheed Martin, 2011
- Lockheed Martin — *The Cyber Kill Chain* (lockheedmartin.com/cyber-kill-chain)
- MITRE ATT&CK — WannaCry S0366, Lazarus Group G0032, Enterprise v19 release
  notes (April 2026)
- Microsoft Security Bulletin MS17-010 (March 2017)
- Europol press release on WannaCry, May 2017
- UK National Audit Office — *Investigation: WannaCry cyber attack and the
  NHS*, 2017
- US DOJ — criminal complaint against Park Jin Hyok, September 2018
- P. Pols — *The Unified Kill Chain*, 2017/2022
