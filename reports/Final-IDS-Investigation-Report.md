# Network Intrusion Detection System — Final Investigation Report

**Project:** Python-Based Network Intrusion Detection System  
**Case Reference:** IDS-LAB-2026-001  
**Environment:** Synthetic Network Traffic Dataset  
**Dataset Date:** 15 October 2026  
**Analyst Role:** SOC Analyst L1 (Training Lab)  
**Investigation Status:** Completed for supplied synthetic dataset  
**Compromise Status:** Not confirmed

---

## 1. Executive Summary

A lightweight Python-based Intrusion Detection System (IDS) was developed to analyze network traffic records and identify potentially suspicious network activity.

The system processed 19 synthetic network traffic records using five rule-based detection mechanisms.

Six alerts were generated and grouped into five investigation cases based on source and destination IP addresses.

The identified patterns included possible port scanning, repeated failed connections, unusually large data transfers, connections to a watchlisted destination port, and repeated network connections.

These findings demonstrate the functionality of the detection rules. They do not establish that an actual intrusion occurred.

## 2. Investigation Objectives

- Analyze synthetic network traffic records.
- Identify potentially suspicious connection patterns.
- Apply time-window-based intrusion detection rules.
- Generate structured security alerts.
- Correlate related alerts into investigation cases.
- Document findings and recommend appropriate investigative actions.

## 3. Tools and Technologies

| Technology | Purpose |
|---|---|
| Python | Network traffic analysis and detection |
| CSV | Synthetic network traffic dataset |
| JSON | Structured alerts and investigation cases |
| Python `datetime` | Time-window correlation |
| Python `collections` | Event grouping and counting |
| Windows Command Prompt | Script execution and verification |

## 4. Evidence Summary

**Primary dataset:** `datasets/synthetic_network_traffic.csv`

**Generated alerts:** `alerts/ids_alerts.json`

**Investigation evidence:** `reports/IDS-Investigation-Report.json`

| Metric | Result |
|---|---:|
| Traffic records analyzed | 19 |
| Invalid records | 0 |
| Detection rules implemented | 5 |
| Raw alerts generated | 6 |
| Investigation cases created | 5 |

All records represent simulated network activity.

## 5. Detection Rules and Findings

### IDS-001 — Possible Port Scanning

**Severity:** Medium

**Source:** `192.0.2.50`  
**Destination:** `198.51.100.10`  
**Destination ports:** 21, 22, 23, 25, 80

Five distinct destination ports were contacted within the configured five-minute detection window.

**Assessment:** The pattern is consistent with possible port enumeration. Legitimate security assessments and administrative tools can produce similar activity.

### IDS-002 — Repeated Failed Connections

**Severity:** Medium

**Source:** `192.0.2.60`  
**Destination:** `198.51.100.30`  
**Destination port:** 22  
**Failed connections:** 5

Five failed connections were identified within the detection window.

**Assessment:** The repeated failures warrant investigation. The available data does not confirm password guessing or unauthorized authentication attempts.

### IDS-003 — Unusual Network Traffic Volume

**Severity:** Medium

**Source:** `192.0.2.70`  
**Destination:** `198.51.100.40`  
**Destination port:** 443  
**Bytes transferred:** 9,500,000

A network record exceeded the configured threshold of 5,000,000 bytes.

**Assessment:** The transfer exceeds the lab's static threshold. Additional baseline and application context would be required to determine whether the volume is abnormal.

### IDS-004 — Watchlisted Destination Port

**Severity:** Medium

**Source:** `192.0.2.80`  
**Destination:** `198.51.100.50`  
**Destination port:** 4444

A connection to the lab-defined watchlisted destination port was detected.

**Assessment:** The port match is a reason for review, not proof of malicious activity.

### IDS-005 — Repeated Network Connections

**Severity:** Medium

The system detected repeated connections associated with two source IP addresses.

- `192.0.2.60` — Five connections to `198.51.100.30:22`
- `192.0.2.90` — Five connections to `198.51.100.60:8080`

**Assessment:** Repeated connections may reflect normal application behavior, connectivity problems, or activity requiring investigation.

## 6. Alert Correlation

The six alerts were grouped into five investigation cases.

| Case ID | Source IP | Related Rules |
|---|---|---|
| CASE-001 | 192.0.2.50 | IDS-001 |
| CASE-002 | 192.0.2.60 | IDS-002, IDS-005 |
| CASE-003 | 192.0.2.70 | IDS-003 |
| CASE-004 | 192.0.2.80 | IDS-004 |
| CASE-005 | 192.0.2.90 | IDS-005 |

CASE-002 contains two alerts describing related connection activity. Grouping them avoids treating the overlapping detections as two independent investigation cases.

## 7. Recommended SOC Investigation Actions

1. Review the affected source and destination systems.
2. Check whether the observed network connections were authorized.
3. Examine relevant firewall, endpoint, and application logs.
4. Compare traffic volumes with established network baselines.
5. Validate whether repeated connection failures resulted from normal connectivity problems.
6. Review the justification for watchlisted destination ports.
7. Escalate findings if additional evidence supports suspicious or unauthorized activity.

## 8. Limitations

The project uses a controlled synthetic dataset rather than live network traffic.

The detection engine operates on CSV records and is not a packet-capturing network sensor.

Static thresholds can produce false positives and may miss suspicious activity that falls below configured thresholds.

The investigation groups alerts using source and destination IP addresses. This provides basic correlation but does not establish incident identity.

No real-world compromise or unauthorized access was confirmed.

## 9. Final Assessment

**Investigation disposition:** Synthetic detection scenarios successfully identified.

**Detection rules tested:** Five.

**Alerts generated:** Six.

**Investigation cases:** Five.

**Containment performed:**