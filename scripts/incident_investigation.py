
import json
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "alerts" / "ids_alerts.json"
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "IDS-Investigation-Report.json"


def investigate_alerts(alerts):
    grouped_alerts = defaultdict(list)

    for alert in alerts:
        key = (
            alert["source_ip"],
            alert["destination_ip"]
        )
        grouped_alerts[key].append(alert)

    cases = []

    for index, (key, related_alerts) in enumerate(
        sorted(grouped_alerts.items()), start=1
    ):
        source_ip, destination_ip = key

        related_alerts.sort(
            key=lambda alert: alert["timestamp"]
        )

        rule_ids = sorted({
            alert["rule_id"]
            for alert in related_alerts
        })

        cases.append({
            "case_id": f"CASE-{index:03d}",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "alert_count": len(related_alerts),
            "rules_triggered": rule_ids,
            "first_alert": related_alerts[0]["timestamp"],
            "last_alert": related_alerts[-1]["timestamp"],
            "status": "Requires analyst review",
            "compromise_confirmed": False,
            "alerts": related_alerts
        })

    return cases


def main():
    if not ALERT_FILE.exists():
        print("ERROR: IDS alert JSON file not found.")
        return

    with ALERT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = data["alerts"]
    cases = investigate_alerts(alerts)

    report = {
        "project": "Network Intrusion Detection System",
        "dataset_type": "Synthetic",
        "total_raw_alerts": len(alerts),
        "total_investigation_cases": len(cases),
        "investigation_cases": cases,
        "conclusion": (
            "Detection patterns identified in synthetic data. "
            "No real-world intrusion has been confirmed."
        )
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n===== IDS INCIDENT INVESTIGATION =====")
    print(f"Raw alerts: {len(alerts)}")
    print(f"Investigation cases: {len(cases)}")

    for case in cases:
        print(f"\n{case['case_id']}")
        print(f"Source: {case['source_ip']}")
        print(f"Destination: {case['destination_ip']}")
        print(f"Alerts: {case['alert_count']}")
        print(f"Rules: {', '.join(case['rules_triggered'])}")
        print(f"Status: {case['status']}")

    print(f"\nReport saved to: {REPORT_FILE}")
    print("Investigation processing completed.")


if __name__ == "__main__":
    main()
