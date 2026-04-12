# MITRE ATT&CK Mapping — DPRK Detection Suite

Comprehensive mapping of all detection rules to MITRE ATT&CK techniques, with references to source intelligence reporting.

## Lazarus Group (HIDDEN COBRA)

| Technique | ID | Tactic | Rule File | Detection Method |
|---|---|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access | `lazarus_credential_harvesting.yar` | YARA — PDB paths, LSASS interaction strings, C2 callbacks |
| Credentials from Password Stores: Browser | T1555.003 | Credential Access | `lazarus_credential_harvesting.yar` | YARA — Browser DB paths, SQLite queries, CryptUnprotectData |
| Input Capture: Keylogging | T1056.001 | Collection | `lazarus_credential_harvesting.yar` | YARA — Keyboard hook APIs, logging patterns, temp staging |
| Remote Services: RDP | T1021.001 | Lateral Movement | `lazarus_lateral_movement.yml` | Sigma — SSH tunneling to RDP ports via Plink/PuTTY |
| Remote Services: SMB | T1021.002 | Lateral Movement | `lazarus_lateral_movement.yml` | Sigma — Tool staging to temp dirs over SMB |
| Windows Management Instrumentation | T1047 | Execution | `lazarus_lateral_movement.yml` | Sigma — WMI-spawned cmd/PowerShell processes |
| Lateral Tool Transfer | T1570 | Lateral Movement | `lazarus_lateral_movement.yml` | Sigma — Executable staging in ProgramData/Temp |

## APT38 (TraderTraitor)

| Technique | ID | Tactic | Rule File | Detection Method |
|---|---|---|---|---|
| Supply Chain Compromise: Software | T1195.002 | Initial Access | `apt38_crypto_theft_tooling.yar` | YARA — Trojanized Electron apps with crypto API access |
| Clipboard Data | T1115 | Collection | `apt38_crypto_theft_tooling.yar` | YARA — Clipboard API hooks with crypto address regex |
| Data from Local System | T1005 | Collection | `apt38_crypto_theft_tooling.yar` | YARA — Wallet file path enumeration, BIP-39 wordlist |
| Data from Local System | T1005 | Collection | `apt38_crypto_wallet_exfil.yml` | Sigma — Access to wallet keystores and browser extensions |
| Exfiltration Over C2 Channel | T1041 | Exfiltration | `apt38_crypto_wallet_exfil.yml` | Sigma — Archive creation followed by HTTP POST/curl |
| Exfiltration Over Web Service | T1567 | Exfiltration | `apt38_crypto_wallet_exfil.yml` | Sigma — Upload to cloud storage post-staging |

## DPRK IT Worker Operations

| Technique | ID | Tactic | Rule File | Detection Method |
|---|---|---|---|---|
| Valid Accounts | T1078 | Initial Access | `dprk_it_worker_indicators.yml` | Sigma — RAT stacking (AnyDesk + TeamViewer concurrent) |
| External Remote Services | T1133 | Initial Access | `dprk_it_worker_indicators.yml` | Sigma — KVM-over-IP + VPN cycling indicators |
| Account Manipulation | T1098 | Persistence | `dprk_it_worker_indicators.yml` | Sigma — Payment method changes, payroll system access via RAT |
| Exfiltration to Cloud Storage | T1567.002 | Exfiltration | `dprk_it_worker_indicators.yml` | Sigma — Git mirror clone followed by cloud storage upload |
| Data from Information Repositories | T1213 | Collection | `dprk_it_worker_indicators.yml` | Sigma — Bulk repository cloning with archive creation |

## Supply Chain (Cross-Actor)

| Technique | ID | Tactic | Rule File | Detection Method |
|---|---|---|---|---|
| Compromise Software Supply Chain | T1195.002 | Initial Access | `dprk_supply_chain_compromise.yar` | YARA — Trojanized installers, malicious npm packages, backdoored builds |

## Coverage Summary

- **Total ATT&CK Techniques Covered:** 17
- **Tactics Covered:** Initial Access, Execution, Persistence, Credential Access, Collection, Lateral Movement, Exfiltration
- **Threat Actors:** Lazarus Group, APT38, APT45, DPRK IT Worker cells
- **Rule Count:** 3 YARA rule files (9 individual rules), 3 Sigma rule files (6 individual rules)
