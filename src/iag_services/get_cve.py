"""
IAG python-script service: look up Cisco PSIRT advisories for a CVE ID.

Params (CLI args):
  --cve_id        The CVE identifier (e.g. CVE-2023-20078)
  --productNames  Include product names in result (optional, default true)
  --summaryDetails Include summary details in result (optional, default true)

Output: JSON to stdout
  { "status": "success", "cve_id": "...", "advisories": [...] }
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta

import requests

CISCO_API_BASE_URL = "https://apix.cisco.com/security/advisories/v2"
CISCO_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"


def get_access_token(client_id: str, client_secret: str) -> str:
    resp = requests.post(
        CISCO_TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=30,
    )
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise ValueError("access_token missing from Cisco token response")
    return token


def get_cve_advisories(token: str, cve_id: str) -> dict:
    resp = requests.get(
        f"{CISCO_API_BASE_URL}/cve/{cve_id}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=30,
    )
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", 60))
        time.sleep(retry_after)
        return get_cve_advisories(token, cve_id)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve_id", required=True)
    parser.add_argument("--productNames", default="true")
    parser.add_argument("--summaryDetails", default="true")
    args = parser.parse_args()

    client_id = os.environ.get("CISCO_API_CLIENT_ID") or os.environ.get("CISCO_OPENVULN_CLIENT_ID")
    client_secret = os.environ.get("CISCO_API_CLIENT_SECRET") or os.environ.get("CISCO_OPENVULN_CLIENT_SECRET")

    if not client_id or not client_secret:
        print(json.dumps({"status": "error", "message": "CISCO_API_CLIENT_ID and CISCO_API_CLIENT_SECRET must be set"}))
        sys.exit(1)

    try:
        token = get_access_token(client_id, client_secret)
        data = get_cve_advisories(token, args.cve_id)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)

    advisories = data.get("advisories", [])
    if not advisories:
        print(json.dumps({"status": "success", "cve_id": args.cve_id, "advisories": []}))
        return

    include_products = args.productNames.lower() not in ("false", "0", "no")
    include_summary = args.summaryDetails.lower() not in ("false", "0", "no")

    formatted = []
    for adv in advisories:
        entry = {
            "advisoryId": adv.get("advisoryId"),
            "title": adv.get("title"),
            "publicationUrl": adv.get("publicationUrl"),
            "sir": adv.get("sir"),
            "severity": adv.get("severity", {}).get("text") if isinstance(adv.get("severity"), dict) else adv.get("sir"),
            "firstPublished": adv.get("firstPublished"),
            "lastUpdated": adv.get("lastUpdated"),
        }
        if include_summary:
            entry["summary"] = adv.get("summary")
        if include_products:
            entry["productNames"] = adv.get("productNames", [])
        formatted.append(entry)

    print(json.dumps({"status": "success", "cve_id": args.cve_id, "advisories": formatted}))


if __name__ == "__main__":
    main()
