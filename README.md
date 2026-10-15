\# Network Intrusion Detection System (IDS)



\*\*Python | Network Security | SOC Analysis | Threat Detection | Incident Investigation\*\*



\## Project Overview



A lightweight, Python-based intrusion detection project that analyzes synthetic network traffic records, applies rule-based detection logic, generates JSON alerts, and groups related findings into investigation cases.



The project demonstrates foundational network security monitoring and SOC investigation skills without requiring a full SIEM platform.



\## Features



\- CSV-based network traffic analysis

\- Five rule-based intrusion detection mechanisms

\- Five-minute sliding-window correlation

\- JSON alert generation

\- Alert grouping and investigation reporting

\- Automated detection testing

\- Lightweight execution on Windows



\## Detection Rules



| Rule ID | Detection | Severity |

|---|---|---|

| IDS-001 | Possible Port Scanning | Medium |

| IDS-002 | Repeated Failed Connections | Medium |

| IDS-003 | Unusually Large Transfer | Medium |

| IDS-004 | Watchlisted Destination Port | Medium |

| IDS-005 | Repeated Connections | Medium |



\## Dataset and Results



The controlled synthetic dataset contains 19 valid network records.



| Metric | Result |

|---|---:|

| Records analyzed | 19 |

| Invalid records | 0 |

| Detection rules | 5 |

| Raw alerts generated | 6 |

| Investigation cases | 5 |



The six alerts were grouped into five investigation cases. Two overlapping alerts describe related activity from the same source and destination.



\## Project Architecture



```text

Synthetic Network Traffic (CSV)

&#x20;             |

&#x20;             v

&#x20;     Traffic Analyzer

&#x20;             |

&#x20;             v

&#x20;    IDS Detection Engine

&#x20;             |

&#x20;             v

&#x20;      JSON Alert Export

&#x20;             |

&#x20;             v

&#x20;     Alert Correlation

&#x20;             |

&#x20;             v

&#x20;     Investigation Report

```



\## Technologies Used



\- Python 3

\- Python standard library (`csv`, `json`, `datetime`, `collections`, `unittest`)

\- Windows Command Prompt

\- CSV and JSON

\- Git and GitHub



\## How to Run



From the project root:



\*\*1. Analyze network traffic\*\*



```bash

py scripts/network\_traffic\_analyzer.py

```



\*\*2. Run the intrusion detection engine\*\*



```bash

py scripts/intrusion\_detection.py

```



\*\*3. Generate investigation cases\*\*



```bash

py scripts/incident\_investigation.py

```



\*\*4. Run automated tests\*\*



```bash

py -m unittest discover -s tests -p "test\_\*.py" -v

```



\## Investigation Findings



The synthetic dataset includes five controlled detection scenarios: port enumeration, repeated failed connections, a large network transfer, a connection to a watchlisted port, and repeated connections to one destination.



All detections are investigative signals rather than evidence of a confirmed attack.



\## Limitations



\- Operates on synthetic CSV network-flow records rather than live packets

\- Does not perform packet inspection or payload analysis

\- Uses fixed detection thresholds

\- May produce false positives

\- Groups alerts by source and destination IP rather than full incident context

\- Is not a replacement for a production IDS or SIEM



\## Future Improvements



\- Additional automated edge-case testing

\- Configurable detection thresholds

\- Alert deduplication and suppression

\- Additional network data sources

\- Improved incident correlation

\- Security dashboards and visualizations



\## Disclaimer



This project was developed for educational and authorized security monitoring. All included traffic records are synthetic. No real-world intrusion or compromise is claimed.

