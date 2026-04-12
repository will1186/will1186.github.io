# DPRK Threat Actor Detection Suite

Detection rules and automated testing framework targeting DPRK-nexus cyber operations — Lazarus Group (HIDDEN COBRA), APT38, and APT45 (Andariel).

YARA rules for malware identification, Sigma rules for behavioral log detection, and a Python framework that validates everything against simulated telemetry.

---

## Coverage

| MITRE ATT&CK Technique | ID | Rule Type | Rule File |
|---|---|---|---|
| OS Credential Dumping | T1003 | YARA | `lazarus_credential_harvesting.yar` |
| Cryptocurrency Theft Tooling | T1496 / T1005 | YARA | `apt38_crypto_theft_tooling.yar` |
| Supply Chain Compromise | T1195.002 | YARA | `dprk_supply_chain_compromise.yar` |
| Lateral Movement via Remote Services | T1021 | Sigma | `lazarus_lateral_movement.yml` |
| Data Exfiltration (Crypto Wallets) | T1041 / T1567 | Sigma | `apt38_crypto_wallet_exfil.yml` |
| DPRK IT Worker Fraud Indicators | T1078 / T1133 | Sigma | `dprk_it_worker_indicators.yml` |

## Structure

```
dprk-detection-suite/
├── rules/
│   ├── yara/                          # File/binary pattern matching
│   │   ├── lazarus_credential_harvesting.yar
│   │   ├── apt38_crypto_theft_tooling.yar
│   │   └── dprk_supply_chain_compromise.yar
│   └── sigma/                         # Log-based behavioral detection
│       ├── lazarus_lateral_movement.yml
│       ├── apt38_crypto_wallet_exfil.yml
│       └── dprk_it_worker_indicators.yml
├── tests/
│   ├── test_framework.py              # Main test runner
│   ├── simulated_logs/
│   │   └── sample_cloud_audit.json    # Synthetic telemetry (benign + malicious)
│   └── scoring/
│       └── detection_scorer.py        # TP/FP/FN scoring engine
└── docs/
    └── attck_mapping.md               # Full ATT&CK technique mapping
```

## Usage

### Run Detection Tests

```bash
pip install pyyaml
cd tests/
python test_framework.py
```

Output:

```
[+] Loading Sigma rules from ../rules/sigma/
[+] Loading simulated logs from simulated_logs/sample_cloud_audit.json
[+] Running detections...

Rule: lazarus_lateral_movement        | TP: 4  | FP: 1  | FN: 0  | Precision: 0.80  | Recall: 1.00
Rule: apt38_crypto_wallet_exfil       | TP: 3  | FP: 0  | FN: 0  | Precision: 1.00  | Recall: 1.00
Rule: dprk_it_worker_indicators       | TP: 5  | FP: 2  | FN: 1  | Precision: 0.71  | Recall: 0.83

Overall Detection Rate: 92.3%  |  False Positive Rate: 8.1%
```

### YARA Scanning

```bash
yara rules/yara/lazarus_credential_harvesting.yar <target_file>
```

## Intelligence Sources

Detection logic derived from publicly available reporting:

- [CISA AA22-108A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a) — TraderTraitor: North Korean State-Sponsored APT Targets Blockchain Companies
- [CISA AA20-106A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a) — Guidance on the North Korean Cyber Threat
- [Mandiant APT38 Report](https://cloud.google.com/blog/topics/threat-intelligence/apt38-details-on-new-north-korean-regime-backed-threat-group) — APT38: Un-usual Suspects
- [Mandiant APT45 Report](https://cloud.google.com/blog/topics/threat-intelligence/apt45-north-korea-digital-military-machine) — APT45: North Korea's Digital Military Machine
- [FBI PIN 20220516-001](https://www.ic3.gov/Media/News/2022/220516.pdf) — North Korean State-Sponsored Actors Target Cryptocurrency
- [DOJ Indictment](https://www.justice.gov/opa/pr/justice-department-charges-five-individuals-multi-year-scheme-generate-revenue-north-korean) — DPRK IT Worker Fraud Indictments (2024)

## Author

**Will Welch** — Threat Intelligence Analyst, Dell Technologies Global Security Organization

## License

MIT
