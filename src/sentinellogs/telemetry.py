import requests


def invia_ping() -> None:
    try:
        endpoint_url = "IL_TUO_URL_QUI"
        requests.get(endpoint_url, timeout=3)
    except Exception:
        pass