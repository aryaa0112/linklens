import csv
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from phishing_detector.training import load_model_artifact, train_model
from phishing_detector.web import LinkLensHandler


class ModelPredictionApiTests(unittest.TestCase):
    def test_single_scan_includes_model_assessment_and_handles_missing_model(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), LinkLensHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/analyze"
        try:
            request = urllib.request.Request(
                url,
                data=json.dumps(
                    {"url": "http://192.0.2.4/login/verify"}
                ).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with (
                patch(
                    "phishing_detector.training.load_model_artifact",
                    return_value={"model": "test"},
                ),
                patch(
                    "phishing_detector.training.predict_analysis",
                    return_value={
                        "score": 4,
                        "label": "benign-pattern",
                        "training_samples": 100,
                        "score_description": "Uncalibrated.",
                    },
                ),
            ):
                with urllib.request.urlopen(request) as response:
                    result = json.load(response)
            self.assertGreaterEqual(result["score"], 25)
            self.assertEqual(result["model"]["status"], "available")
            self.assertEqual(result["model"]["score"], 4)

            with patch(
                "phishing_detector.training.load_model_artifact",
                side_effect=FileNotFoundError("not trained"),
            ):
                with urllib.request.urlopen(request) as response:
                    result = json.load(response)
            self.assertEqual(result["model"]["status"], "unavailable")
            self.assertIn("not trained", result["model"]["message"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_predict_endpoint_uses_trained_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "urls.csv"
            artifact_path = root / "model.joblib"
            with dataset.open("w", encoding="utf-8", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(["url", "label"])
                for index in range(10):
                    writer.writerow(
                        [f"https://docs{index}.example.com/page{index}", "benign"]
                    )
                    writer.writerow(
                        [
                            f"http://secure-login-{index}.invalid/login?verify={index}",
                            "phishing",
                        ]
                    )
            train_model(dataset, artifact_path)
            artifact = load_model_artifact(artifact_path)

            server = ThreadingHTTPServer(("127.0.0.1", 0), LinkLensHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/predict",
                    data=json.dumps({"url": "https://docs.example.com"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with patch(
                    "phishing_detector.training.load_model_artifact",
                    return_value=artifact,
                ):
                    with urllib.request.urlopen(request) as response:
                        result = json.load(response)
                        self.assertEqual(response.status, 200)
                        self.assertIn("Content-Security-Policy", response.headers)
                self.assertIn("score", result)
                self.assertIn("Uncalibrated", result["score_description"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_predict_endpoint_explains_missing_model(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), LinkLensHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/api/predict",
            data=json.dumps({"url": "https://example.com"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with patch(
                "phishing_detector.training.load_model_artifact",
                side_effect=FileNotFoundError("not trained"),
            ):
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request)
            self.assertEqual(error.exception.code, 503)
            body = json.load(error.exception)
            self.assertIn("No trained model", body["error"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
