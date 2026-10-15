
import json
from pathlib import Path

from collections import defaultdict
from datetime import timedelta

from network_traffic_analyzer import load_traffic

WINDOW = timedelta(minutes=5)
PORT_THRESHOLD = 5
FAILURE_THRESHOLD = 5


# IDS-001: Port Scan Detection
def detect_port_scans(records):
    connections = defaultdict(list)
    alerts = []
    alerted_keys = set()

    for record in records:
        key = (
            record["source_ip"],
            record["destination_ip"]
        )

        timestamp = record["timestamp"]

        connections[key].append(
            (timestamp, record["port"])
        )

        connections[key] = [
            (time, port)
            for time, port in connections[key]
            if timedelta(0) <= timestamp - time <= WINDOW
        ]

        unique_ports = {
            port for _, port in connections[key]
        }

        if len(unique_ports) < PORT_THRESHOLD:
            alerted_keys.discard(key)

        if (
            len(unique_ports) >= PORT_THRESHOLD
            and key not in alerted_keys
        ):
            alerts.append({
                "rule_id": "IDS-001",
                "severity": "MEDIUM",
                "description": "Possible port scanning activity",
                "timestamp": timestamp.isoformat(),
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "unique_ports": sorted(unique_ports)
            })

            alerted_keys.add(key)

    return alerts


# IDS-002: Repeated Failed Connections
def detect_failed_connections(records):
    failures = defaultdict(list)
    alerts = []
    alerted_keys = set()

    for record in records:
        key = (
            record["source_ip"],
            record["destination_ip"],
            record["port"]
        )

        timestamp = record["timestamp"]

        failures[key] = [
            time for time in failures[key]
            if timedelta(0) <= timestamp - time <= WINDOW
        ]

        if len(failures[key]) < FAILURE_THRESHOLD:
            alerted_keys.discard(key)

        if record["status"] != "FAILED":
            continue

        failures[key].append(timestamp)

        if (
            len(failures[key]) >= FAILURE_THRESHOLD
            and key not in alerted_keys
        ):
            alerts.append({
                "rule_id": "IDS-002",
                "severity": "MEDIUM",
                "description": "Repeated failed connections",
                "timestamp": timestamp.isoformat(),
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "destination_port": record["port"],
                "failed_connections": len(failures[key])
            })

            alerted_keys.add(key)

    return alerts


# IDS-003: Unusual Traffic Volume Detection
def detect_unusual_traffic_volume(records):
    alerts = []
    byte_threshold = 5_000_000

    for record in records:
        if record["bytes"] >= byte_threshold:
            alerts.append({
                "rule_id": "IDS-003",
                "severity": "MEDIUM",
                "description": "Unusually large network transfer",
                "timestamp": record["timestamp"].isoformat(),
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "destination_port": record["port"],
                "bytes_transferred": record["bytes"]
            })

    return alerts


# IDS-004: Watchlisted Destination Port Detection
def detect_watchlisted_ports(records):
    alerts = []
    watchlisted_ports = {4444}

    for record in records:
        if record["port"] in watchlisted_ports:
            alerts.append({
                "rule_id": "IDS-004",
                "severity": "MEDIUM",
                "description": "Connection to watchlisted port",
                "timestamp": record["timestamp"].isoformat(),
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "destination_port": record["port"]
            })

    return alerts


# IDS-005: Repeated Connection Detection
def detect_repeated_connections(records):
    connections = defaultdict(list)
    alerts = []
    alerted_keys = set()

    for record in records:
        key = (
            record["source_ip"],
            record["destination_ip"],
            record["port"]
        )

        timestamp = record["timestamp"]

        connections[key] = [
            time for time in connections[key]
            if timedelta(0) <= timestamp - time <= WINDOW
        ]

        if len(connections[key]) < 5:
            alerted_keys.discard(key)

        connections[key].append(timestamp)

        if (
            len(connections[key]) >= 5
            and key not in alerted_keys
        ):
            alerts.append({
                "rule_id": "IDS-005",
                "severity": "MEDIUM",
                "description": "Repeated connections to one destination",
                "timestamp": timestamp.isoformat(),
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "destination_port": record["port"],
                "connection_count": len(connections[key])
            })

            alerted_keys.add(key)

    return alerts

# Phase 5: Export IDS alerts to JSON
def export_alerts(alerts, total_records, invalid_rows):
    base_dir = Path(__file__).resolve().parent.parent
    alert_dir = base_dir / "alerts"
    alert_dir.mkdir(parents=True, exist_ok=True)

    output_file = alert_dir / "ids_alerts.json"

    report = {
        "project": "Network Intrusion Detection System",
        "dataset_type": "Synthetic",
        "records_analyzed": total_records,
        "invalid_rows": invalid_rows,
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_file

def main():
    try:
        records, invalid_rows = load_traffic()

        
        alerts = (
            detect_port_scans(records)
            + detect_failed_connections(records)
            + detect_unusual_traffic_volume(records)
            + detect_watchlisted_ports(records)
            + detect_repeated_connections(records)
        )


        alerts.sort(key=lambda alert: alert["timestamp"])

        print("\n===== INTRUSION DETECTION SYSTEM =====")
        print(f"Records analyzed: {len(records)}")
        print(f"Invalid rows: {invalid_rows}")
        print(f"Alerts generated: {len(alerts)}")

        for alert in alerts:
            print(
                f"\n[{alert['severity']}] {alert['rule_id']}"
                f"\nDescription: {alert['description']}"
                f"\nTimestamp: {alert['timestamp']}"
                f"\nSource IP: {alert['source_ip']}"
                f"\nDestination IP: {alert['destination_ip']}"
            )

            if "unique_ports" in alert:
                print(f"Ports: {alert['unique_ports']}")

            if "destination_port" in alert:
                print(
                    f"Destination Port: "
                    f"{alert['destination_port']}"
                )

            if "failed_connections" in alert:
                print(
                    f"Failed Connections: "
                    f"{alert['failed_connections']}"
                )
             
            if "bytes_transferred" in alert:
                print(
                    f"Bytes Transferred: "
                    f"{alert['bytes_transferred']:,}"
                )
            
            if "connection_count" in alert:
                print(
                    f"Connection Count: "
                    f"{alert['connection_count']}"
                )
             
        output_file = export_alerts(
            alerts,
            len(records),
            invalid_rows
        )

        print(f"\nJSON alerts saved to: {output_file}")

        print("\nDetection completed.")

    except (OSError, ValueError) as error:
        print(f"ERROR: {error}")


if __name__ == "__main__":
    main()
