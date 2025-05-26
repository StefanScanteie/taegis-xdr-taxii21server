import pandas as pd
from stix2 import Indicator, Bundle
import requests
import argparse
from datetime import datetime

TAXII_ENDPOINT = "http://host.docker.internal:5050/taxii2/root/collections/default/objects/"

def sanitize_ip(ip):
    return ip.replace("[.]", ".")

def push_bundle(bundle):
    r = requests.post(
        TAXII_ENDPOINT,
        headers={"Content-Type": "application/vnd.oasis.stix+json; version=2.1"},
        data=bundle.serialize()
    )
    print(f"Upload status: {r.status_code}")
    if r.status_code != 202:
        print(r.text)

def import_from_excel(file):
    df = pd.read_excel(file)
    indicators = []

    for _, row in df.iterrows():
        ip = sanitize_ip(str(row["value"]).strip())
        threat = row.get("Threat Desc", "IOC")
        timestamp = pd.to_datetime(row["Published Date"]).isoformat()

        pattern = f"[ipv4-addr:value = '{ip}']"
        indicators.append(Indicator(
            name=f"IOC: {ip}",
            description=threat,
            pattern=pattern,
            pattern_type="stix",
            valid_from=timestamp
        ))

    push_bundle(Bundle(objects=indicators))

def manual_entry(ip, threat, date_str):
    # Convert date to full ISO format (e.g., 2025-05-26 → 2025-05-26T00:00:00Z)
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        iso_date = dt.isoformat() + "Z"
    except ValueError:
        print("Error: Invalid date format. Use YYYY-MM-DD.")
        return

    pattern = f"[ipv4-addr:value = '{sanitize_ip(ip)}']"
    indicator = Indicator(
        name=f"Manual IOC: {ip}",
        description=threat,
        pattern=pattern,
        pattern_type="stix",
        valid_from=iso_date
    )
    push_bundle(Bundle(objects=[indicator]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="Excel file to import")
    parser.add_argument("--manual", action="store_true", help="Manually add IOC")
    parser.add_argument("--ip", help="IOC IP address")
    parser.add_argument("--threat", help="Threat description")
    parser.add_argument("--date", help="Valid from date (YYYY-MM-DD)")

    args = parser.parse_args()

    if args.manual:
        if not all([args.ip, args.threat, args.date]):
            print("Manual mode requires --ip, --threat, and --date")
        else:
            manual_entry(args.ip, args.threat, args.date)
    elif args.file:
        import_from_excel(args.file)
    else:
        print("Provide either --file <excel> or use --manual with --ip --threat --date")
