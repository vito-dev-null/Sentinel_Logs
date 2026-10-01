import os

import requests

def invia_ping() -> None:
    endpoint_url = os.environ.get("SENTINELLOGS_TELEMETRY_URL")
    if not endpoint_url:
        return
    try:
        requests.get(endpoint_url, timeout=3)
    except Exception:
        pass