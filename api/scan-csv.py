from __future__ import annotations

import csv
import io
import json
from http.server import BaseHTTPRequestHandler
from typing import Any

from src.features import extract_features, normalize_url
from api.index import assess


class handler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_100_000:
                self._json(400, {"detail": "CSV request is empty or exceeds the 2 MB limit."})
                return

            payload = json.loads(self.rfile.read(length))
            csv_text = payload.get("csv_text") if isinstance(payload, dict) else None
            if not isinstance(csv_text, str) or not csv_text.strip():
                self._json(400, {"detail": "Upload CSV text to scan."})
                return

            reader = csv.DictReader(io.StringIO(csv_text))
            if not reader.fieldnames or "url" not in {name.strip() for name in reader.fieldnames}:
                self._json(400, {"detail": "CSV must contain a column named url."})
                return

            rows = []
            scanned = 0
            skipped = 0
            for row in reader:
                if scanned + skipped >= 1000:
                    break
                raw_url = (row.get("url") or "").strip()
                if not raw_url:
                    skipped += 1
                    continue
                try:
                    normalized = normalize_url(raw_url)
                    features = extract_features(normalized)
                    result = assess(features)
                    rows.append({
                        "url": normalized,
                        "model_result": ("Potential phishing" if result["prediction"] == 1 else "Likely legitimate (model class)") if result["prediction"] is not None else "Heuristic only (no model file)",
                        "model_confidence": result["model_confidence"],
                        "rule_score": result["risk_score"],
                        "warning_signals": "; ".join(result["reasons"]),
                        "validation": "OK",
                    })
                    scanned += 1
                except ValueError as exc:
                    rows.append({
                        "url": raw_url,
                        "model_result": "Not analyzed",
                        "model_confidence": None,
                        "rule_score": "",
                        "warning_signals": "",
                        "validation": str(exc),
                    })
                    skipped += 1

            self._json(200, {"rows": rows, "scanned": scanned, "skipped": skipped, "limit": 1000})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"detail": "Request body must contain valid JSON."})
        except Exception:
            self._json(500, {"detail": "The CSV scanning service encountered an internal error."})

    def do_GET(self) -> None:
        self._json(200, {"status": "ok", "service": "PhishShield CSV scanner"})
