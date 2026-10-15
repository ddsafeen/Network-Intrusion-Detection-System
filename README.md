# Network Intrusion Detection System (IDS)

**Python | Network Security | SOC Analysis | Threat Detection | Incident Investigation**

## Project Overview

A lightweight, Python-based intrusion detection project that analyzes synthetic network traffic records, applies rule-based detection logic, generates JSON alerts, and groups related findings into investigation cases.

The project demonstrates foundational network security monitoring and SOC investigation skills without requiring a full SIEM platform.

## Key Features

- CSV-based network traffic analysis
- Five rule-based intrusion detection mechanisms
- Five-minute sliding-window correlation
- JSON alert generation
- Alert grouping and incident investigation
- Automated unit testing
- Lightweight Windows-compatible implementation

## Detection Rules

| Rule ID | Detection | Severity |
|---|---|---|
| IDS-001 | Possible Port Scanning | Medium |
| IDS-002 | Repeated Failed Connections | Medium |
| IDS-003 | Unusually Large Network Transfer | Medium |
| IDS-004 | Watchlisted Destination Port | Medium |
| IDS-005 | Repeated Network Connections | Medium |

## Detection Results

The synthetic dataset contains 19 valid network traffic records.

| Metric | Result |
|---|---:|
| Records analyzed | 19 |
| Invalid records | 0 |
| Detection rules implemented | 5 |
| Alerts generated | 6 |
| Investigation cases | 5 |

Six alerts were generated across five detection rules. Two related alerts were grouped into one investigation case.
## Automated Testing

The project includes automated unit tests for its five detection rules, covering expected detections, non-detections, and time-window boundaries.

Run the tests using:

`py -m unittest discover -s tests -p "test_*.py" -v`

**Test evidence:**

![Automated IDS Unit Tests](screenshots/05-unit-tests.png)

## Project Architecture

Synthetic Network Traffic (CSV)

↓

Network Traffic Analyzer

↓

Rule-Based IDS Detection Engine

↓

JSON Alert Export

↓

Alert Correlation

↓

Investigation Report

## Technologies Used

- Python 3
- Python standard library: csv, json, datetime, collections, pathlib, unittest
- Windows Command Prompt
- CSV and JSON
- Git and GitHub

## How to Run

**Requirements:** Python 3 and the included synthetic dataset.

Run the following commands from the project root.

**1. Analyze network traffic**

`py scripts/network_traffic_analyzer.py`

**2. Run the IDS detection engine**

`py scripts/intrusion_detection.py`

**3. Generate investigation cases**

`py scripts/incident_investigation.py`

**4. Execute automated tests**

`py -m unittest discover -s tests -p "test_*.py" -v`

## Investigation Findings

The controlled dataset contains five simulated detection scenarios:

1. Possible port scanning involving five destination ports.
2. Repeated failed connections to port 22.
3. A network transfer exceeding the configured five-million-byte threshold.
4. A connection to watchlisted destination port 4444.
5. Repeated connections to a single destination.

The findings represent detection signals requiring analyst review. They do not establish malicious intent or confirm an actual intrusion.

## Investigation Evidence

- `datasets/synthetic_network_traffic.csv` — Synthetic network traffic records
- `alerts/ids_alerts.json` — Generated detection alerts
- `reports/IDS-Investigation-Report.json` — Correlated investigation cases
- `reports/Final-IDS-Investigation-Report.md` — Final investigation report
- `tests/test_intrusion_detection.py` — Automated detection tests
- `screenshots/` — Supporting execution evidence

## Limitations

- Uses synthetic CSV traffic rather than live network capture
- Does not inspect packet payloads
- Uses fixed thresholds that may generate false positives
- Performs basic alert correlation based on source and destination IPs
- Does not automatically block suspicious connections
- Is not a replacement for a production IDS or SIEM

## Future Improvements

- Configurable detection thresholds
- Improved alert deduplication
- Additional automated edge-case testing
- Support for additional network data sources
- More advanced event correlation
- Security monitoring dashboards

## Disclaimer

This project was developed for educational and authorized cybersecurity training. All included traffic records are synthetic. No real-world intrusion or compromise is claimed.
