from __future__ import annotations

import base64
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def _request_json(url: str, *, method: str = "GET", payload: dict | None = None,
                  headers: dict | None = None, timeout: int = 7) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=data, headers=headers or {}, method=method)
    with urlopen(request, timeout=timeout) as response:
        raw = response.read(1_000_000)
        return json.loads(raw.decode("utf-8") or "{}")


def check_google_safe_browsing(url: str) -> dict:
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return {"provider": "Google Safe Browsing", "status": "not_configured",
                "message": "API key not configured"}
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?" + urlencode({"key": key})
    payload = {
        "client": {"clientId": "phishshield", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        data = _request_json(endpoint, method="POST", payload=payload,
                             headers={"Content-Type": "application/json"})
        matches = data.get("matches") or []
        if matches:
            kinds = sorted({item.get("threatType", "UNKNOWN") for item in matches})
            return {"provider": "Google Safe Browsing", "status": "malicious",
                    "message": "Listed as a known threat", "threat_types": kinds}
        return {"provider": "Google Safe Browsing", "status": "clean",
                "message": "No match in the queried threat lists"}
    except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
        code = getattr(exc, "code", None)
        return {"provider": "Google Safe Browsing", "status": "unavailable",
                "message": f"Lookup unavailable (HTTP {code})" if code else "Lookup unavailable"}


def check_virustotal(url: str) -> dict:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return {"provider": "VirusTotal", "status": "not_configured",
                "message": "API key not configured"}
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        data = _request_json(endpoint, headers={"x-apikey": key, "accept": "application/json"})
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(value or 0) for value in stats.values())
        if malicious or suspicious:
            return {"provider": "VirusTotal", "status": "malicious",
                    "message": "Existing report contains detections",
                    "malicious": malicious, "suspicious": suspicious, "engines_total": total}
        if total:
            return {"provider": "VirusTotal", "status": "clean",
                    "message": "No detections in the available existing report",
                    "malicious": 0, "suspicious": 0, "engines_total": total}
        return {"provider": "VirusTotal", "status": "unknown",
                "message": "Existing report has no completed engine results"}
    except HTTPError as exc:
        if exc.code == 404:
            return {"provider": "VirusTotal", "status": "unknown",
                    "message": "No existing report; URL was not submitted for scanning"}
        return {"provider": "VirusTotal", "status": "unavailable",
                "message": f"Lookup unavailable (HTTP {exc.code})"}
    except (URLError, TimeoutError, ValueError, OSError):
        return {"provider": "VirusTotal", "status": "unavailable",
                "message": "Lookup unavailable"}


def check_reputation(url: str) -> dict:
    checks = [check_google_safe_browsing(url), check_virustotal(url)]
    statuses = [item["status"] for item in checks]
    if "malicious" in statuses:
        verdict = "threat_detected"
    else:
        configured = [status for status in statuses if status not in {"not_configured"}]
        if configured and all(status == "clean" for status in configured) and len(configured) == len(statuses):
            verdict = "no_known_threats_detected"
        else:
            verdict = "inconclusive"
    return {"verdict": verdict, "checks": checks}
