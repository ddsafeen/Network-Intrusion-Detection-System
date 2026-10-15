
import sys
import unittest
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "scripts"))

from intrusion_detection import (
    detect_port_scans,
    detect_failed_connections,
    detect_unusual_traffic_volume,
    detect_watchlisted_ports,
    detect_repeated_connections,
)


START = datetime(2026, 10, 15, 10, 0, 0)


def make_record(
    seconds=0,
    source="192.0.2.10",
    destination="198.51.100.10",
    port=80,
    status="SUCCESS",
    byte_count=1000,
):
    return {
        "timestamp": START + timedelta(seconds=seconds),
        "source_ip": source,
        "destination_ip": destination,
        "port": port,
        "status": status,
        "bytes": byte_count,
    }


class TestIntrusionDetection(unittest.TestCase):

    def test_port_scan_detected(self):
        records = [
            make_record(seconds=i * 10, port=port)
            for i, port in enumerate([21, 22, 23, 25, 80])
        ]
        alerts = detect_port_scans(records)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IDS-001")

    def test_normal_ports_not_flagged(self):
        records = [
            make_record(seconds=i * 10, port=port)
            for i, port in enumerate([80, 443, 8080])
        ]
        self.assertEqual(detect_port_scans(records), [])

    def test_failed_connections_detected(self):
        records = [
            make_record(seconds=i * 10, port=22, status="FAILED")
            for i in range(5)
        ]
        alerts = detect_failed_connections(records)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IDS-002")

    def test_four_failures_not_flagged(self):
        records = [
            make_record(seconds=i * 10, port=22, status="FAILED")
            for i in range(4)
        ]
        self.assertEqual(detect_failed_connections(records), [])

    def test_large_transfer_detected(self):
        records = [make_record(byte_count=9_500_000)]
        alerts = detect_unusual_traffic_volume(records)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IDS-003")

    def test_small_transfer_not_flagged(self):
        records = [make_record(byte_count=1000)]
        self.assertEqual(
            detect_unusual_traffic_volume(records), []
        )

    def test_watchlisted_port_detected(self):
        records = [make_record(port=4444)]
        alerts = detect_watchlisted_ports(records)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IDS-004")

    def test_normal_port_not_watchlisted(self):
        records = [make_record(port=443)]
        self.assertEqual(
            detect_watchlisted_ports(records), []
        )

    def test_repeated_connections_detected(self):
        records = [
            make_record(seconds=i * 10, port=8080)
            for i in range(5)
        ]
        alerts = detect_repeated_connections(records)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "IDS-005")

    def test_four_connections_not_flagged(self):
        records = [
            make_record(seconds=i * 10, port=8080)
            for i in range(4)
        ]
        self.assertEqual(
            detect_repeated_connections(records), []
        )
    
    def test_port_scan_outside_window(self):
        records = [
            make_record(seconds=i * 400, port=port)
            for i, port in enumerate([21, 22, 23, 25, 80])
        ]

        alerts = detect_port_scans(records)
        self.assertEqual(alerts, [])

    def test_failed_connections_outside_window(self):
        records = [
            make_record(
                seconds=i * 400,
                port=22,
                status="FAILED"
            )
            for i in range(5)
        ]

        alerts = detect_failed_connections(records)
        self.assertEqual(alerts, [])

    def test_repeated_connections_outside_window(self):
        records = [
            make_record(seconds=i * 400, port=8080)
            for i in range(5)
        ]

        alerts = detect_repeated_connections(records)
        self.assertEqual(alerts, [])

if __name__ == "__main__":
    unittest.main()
