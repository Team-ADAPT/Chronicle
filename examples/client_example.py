#!/usr/bin/env python3
"""
Chronicle Security Tool Service — External Client Example
=========================================================
Demonstrates querying the Chronicle read-only service API using only the
Python standard library.

Configuration
-------------
CHRONICLE_BASE_URL   Base URL of the service. Default: http://127.0.0.1:8765
CHRONICLE_API_KEY    API key if the service requires one (optional).

Run
---
    CHRONICLE_BASE_URL=http://127.0.0.1:8765 python examples/client_example.py

No secrets are embedded in this file.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

BASE_URL = os.environ.get("CHRONICLE_BASE_URL", "http://127.0.0.1:8765").rstrip("/")
API_KEY = os.environ.get("CHRONICLE_API_KEY", "")


def _get(path: str, params: dict | None = None) -> dict:
    url = f"{BASE_URL}{path}"
    if params:
        url += "?" + urlencode(params)
    req = urllib.request.Request(url, method="GET")
    if API_KEY:
        req.add_header("X-Chronicle-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())
        print(f"  HTTP {exc.code}: {body}", file=sys.stderr)
        return body
    except Exception as exc:
        print(f"  Request failed: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    print(f"Chronicle Security Tool Service Client")
    print(f"Base URL: {BASE_URL}\n")

    # 1. Health check
    print("=== GET /api/v1/health ===")
    health = _get("/api/v1/health")
    print(json.dumps(health, indent=2))

    # 2. List alerts (first page, limit 5)
    print("\n=== GET /api/v1/alerts?limit=5 ===")
    alerts_page = _get("/api/v1/alerts", params={"limit": 5})
    pagination = alerts_page.get("pagination", {})
    print(f"Total alerts in buffer: {pagination.get('total', 'n/a')}")
    for alert in alerts_page.get("alerts", []):
        print(
            f"  [{alert.get('riskCategory', '?'):8s}] {alert.get('id')}  "
            f"score={alert.get('riskScore')}  "
            f"source={alert.get('detection_source')}  "
            f"comm={alert.get('comm')}"
        )

    # 3. Fetch a specific alert by ID (if any exist)
    alerts = alerts_page.get("alerts", [])
    if alerts:
        alert_id = alerts[0]["id"]
        print(f"\n=== GET /api/v1/alerts/{alert_id} ===")
        detail = _get(f"/api/v1/alerts/{alert_id}")
        alert = detail.get("alert", {})
        print(f"  id:               {alert.get('id')}")
        print(f"  risk_score:       {alert.get('riskScore')}")
        print(f"  risk_category:    {alert.get('riskCategory')}")
        print(f"  eval_status:      {alert.get('eval_status')}")
        print(f"  detection_source: {alert.get('detection_source')}")
        print(f"  description:      {alert.get('description', '')[:80]}")
        sigs = alert.get("contributing_signals", [])
        if sigs:
            print(f"  signals ({len(sigs)}):")
            for s in sigs[:3]:
                print(f"    • [{s['source']}] {s['name']} (+{s['score_contribution']})")
    else:
        print("\nNo alerts in buffer (pipeline may not have detected anomalies yet).")


if __name__ == "__main__":
    main()
