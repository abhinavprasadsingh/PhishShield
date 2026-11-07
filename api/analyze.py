from __future__ import annotations

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
            if length <= 0 or length > 16_384:
                self._json(400, {"detail": "Request body is empty or too large."})
                return

            payload = json.loads(self.rfile.read(length))
            raw_url = payload.get("url") if isinstance(payload, dict) else None
            if not isinstance(raw_url, str) or not raw_url.strip():
                self._json(400, {"detail": "Enter a URL to analyze."})
                return
            if len(raw_url) > 2048:
                self._json(400, {"detail": "URL must be 2,048 characters or fewer."})
                return

            normalized = normalize_url(raw_url)
            features = extract_features(normalized)
            result = assess(features, normalized)
            self._json(200, {"url": normalized, **result})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"detail": "Request body must contain valid JSON."})
        except ValueError as exc:
            self._json(400, {"detail": str(exc)})
        except Exception:
            self._json(500, {"detail": "The URL analysis service encountered an internal error."})

    def do_GET(self) -> None:
        self._json(200, {"status": "ok", "service": "PhishShield URL analyzer"})
