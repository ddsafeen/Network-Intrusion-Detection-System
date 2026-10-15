
import csv
import ipaddress
from pathlib import Path
from datetime import datetime
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET = BASE_DIR / "datasets" / "synthetic_network_traffic.csv"

REQUIRED_COLUMNS = {
    "Timestamp",
    "SourceIP",
    "DestinationIP",
    "DestinationPort",
    "Protocol",
    "Status",
    "BytesTransferred"
}


def parse_timestamp(value):
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue

    raise ValueError(f"Unsupported timestamp: {value}")


def load_traffic():
    records = []
    invalid_rows = 0

    with DATASET.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(
            reader.fieldnames
        ):
            raise ValueError("Dataset has missing CSV columns.")

        for line_number, row in enumerate(reader, start=2):
            try:
                record = {
                    
"timestamp": parse_timestamp(row["Timestamp"]),

                    "source_ip": str(
                        ipaddress.ip_address(row["SourceIP"])
                    ),
                    "destination_ip": str(
                        ipaddress.ip_address(row["DestinationIP"])
                    ),
                    "port": int(row["DestinationPort"]),
                    "protocol": row["Protocol"].upper(),
                    "status": row["Status"].upper(),
                    "bytes": int(row["BytesTransferred"])
                }

                if not 1 <= record["port"] <= 65535:
                    raise ValueError("Invalid destination port")

                if record["bytes"] < 0:
                    raise ValueError("Negative byte count")

                if record["protocol"] not in {"TCP", "UDP"}:
                    raise ValueError("Unsupported protocol")

                if record["status"] not in {"SUCCESS", "FAILED"}:
                    raise ValueError("Unsupported status")

                records.append(record)

            except (ValueError, TypeError, KeyError) as error:
                invalid_rows += 1
                print(
                    f"[WARNING] Skipping row {line_number}: {error}"
                )

    return sorted(records, key=lambda r: r["timestamp"]), invalid_rows


def analyze_traffic(records):
    sources = Counter(r["source_ip"] for r in records)
    protocols = Counter(r["protocol"] for r in records)
    statuses = Counter(r["status"] for r in records)

    total_bytes = sum(r["bytes"] for r in records)

    print("\n===== NETWORK TRAFFIC ANALYSIS =====")
    print(f"Total Records: {len(records)}")
    print(f"Total Bytes Transferred: {total_bytes}")

    print("\n===== PROTOCOL DISTRIBUTION =====")
    for protocol, count in sorted(protocols.items()):
        print(f"{protocol}: {count}")

    print("\n===== CONNECTION STATUS =====")
    for status, count in sorted(statuses.items()):
        print(f"{status}: {count}")

    print("\n===== SOURCE IP DISTRIBUTION =====")
    for source, count in sorted(sources.items()):
        print(f"{source}: {count}")

    print("\nAnalysis completed.")


def main():
    if not DATASET.exists():
        print("ERROR: Network dataset not found.")
        return

    try:
        records, invalid_rows = load_traffic()
        analyze_traffic(records)
        print(f"Invalid Rows Skipped: {invalid_rows}")

    except (OSError, csv.Error, ValueError) as error:
        print(f"ERROR: {error}")


if __name__ == "__main__":
    main()
