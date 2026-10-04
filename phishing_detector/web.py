"""Local web dashboard and JSON API for LinkLens."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .features import analyze_url
from .scoring import assess_analysis, assess_url

STATIC_DIR = Path(__file__).with_name("static")
MAX_BODY_BYTES = 64 * 1024
MAX_BATCH_URLS = 100
MAX_URL_LENGTH = 8192


class LinkLensHandler(BaseHTTPRequestHandler):
    server_version = "LinkLens/1.0"

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._serve_static("index.html", "text/html; charset=utf-8")
            return
        if path == "/styles.css":
            self._serve_static("styles.css", "text/css; charset=utf-8")
            return
        if path == "/app.js":
            self._serve_static("app.js", "text/javascript; charset=utf-8")
            return
        self._send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in {"/api/analyze", "/api/batch", "/api/predict"}:
            self._send_json(404, {"error": "Not found."})
            return

        if path == "/api/predict":
            self._predict()
            return

        try:
            payload = self._read_json()
            if path == "/api/analyze":
                value = payload.get("url")
                if not isinstance(value, str):
                    raise ValueError("Provide a URL as text.")
                if len(value) > MAX_URL_LENGTH:
                    raise ValueError(f"URLs cannot exceed {MAX_URL_LENGTH} characters.")
                analysis = analyze_url(value)
                result = assess_analysis(analysis).as_dict()
                result["model"] = self._model_assessment(analysis)
                self._send_json(200, result)
                return

            values = payload.get("urls")
            if not isinstance(values, list) or not values:
                raise ValueError("Provide at least one URL.")
            if len(values) > MAX_BATCH_URLS:
                raise ValueError(f"Analyze no more than {MAX_BATCH_URLS} URLs at once.")

            results = []
            for index, value in enumerate(values, start=1):
                if not isinstance(value, str):
                    results.append({"row": index, "url": str(value), "error": "URL must be text."})
                    continue
                try:
                    if len(value) > MAX_URL_LENGTH:
                        raise ValueError(f"URLs cannot exceed {MAX_URL_LENGTH} characters.")
                    results.append({"row": index, **assess_url(value).as_dict()})
                except ValueError as error:
                    results.append({"row": index, "url": value, "error": str(error)})
            self._send_json(200, {"results": results})
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json(400, {"error": str(error)})

    @staticmethod
    def _model_assessment(analysis: Any) -> dict[str, object]:
        try:
            from .training import load_model_artifact, predict_analysis

            artifact = load_model_artifact()
            return {"status": "available", **predict_analysis(analysis, artifact)}
        except (ImportError, FileNotFoundError) as error:
            return {"status": "unavailable", "message": str(error)}
        except (OSError, ValueError) as error:
            return {"status": "error", "message": f"Could not load trained model: {error}"}

    def _predict(self) -> None:
        try:
            payload = self._read_json()
            value = payload.get("url")
            if not isinstance(value, str):
                raise ValueError("Provide a URL as text.")
            if len(value) > MAX_URL_LENGTH:
                raise ValueError(f"URLs cannot exceed {MAX_URL_LENGTH} characters.")
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return

        try:
            from .training import load_model_artifact, predict_analysis
        except ImportError:
            self._send_json(
                503,
                {"error": "Install the ML dependencies with python -m pip install -r requirements.txt."},
            )
            return

        try:
            artifact = load_model_artifact()
        except FileNotFoundError:
            self._send_json(
                503,
                {"error": "No trained model is available. Train one with python -m phishing_detector.training."},
            )
            return
        except (OSError, ValueError) as error:
            self._send_json(500, {"error": f"Could not load the trained model: {error}"})
            return

        try:
            from .features import analyze_url

            analysis = analyze_url(value)
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
            return
        self._send_json(200, predict_analysis(analysis, artifact))

    def _read_json(self) -> dict[str, Any]:
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            raise ValueError("A JSON request body is required.")
        try:
            length = int(content_length)
        except ValueError as error:
            raise ValueError("Invalid request body length.") from error
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body is too large.")
        raw_body = self.rfile.read(length)
        try:
            payload = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Request body must be valid JSON.") from error
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object.")
        return payload

    def _serve_static(self, filename: str, content_type: str) -> None:
        content = (STATIC_DIR / filename).read_bytes()
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _security_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; style-src 'self'; "
            "script-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def log_message(self, format: str, *args: object) -> None:
        super().log_message(format, *args)


def serve(port: int = 8765) -> None:
    """Run the dashboard on loopback so it is not exposed to the local network."""
    server = ThreadingHTTPServer(("127.0.0.1", port), LinkLensHandler)
    print(f"LinkLens is running at http://127.0.0.1:{port}")
    print("Scans stay on this computer. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping LinkLens.")
    finally:
        server.server_close()
