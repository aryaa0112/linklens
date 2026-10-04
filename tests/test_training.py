import csv
import tempfile
import unittest
from pathlib import Path

from phishing_detector.training import _group_holdout, predict_url, train_model


class TrainingPipelineTests(unittest.TestCase):
    def _write_dataset(self, path):
        with path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(["url", "label"])
            for index in range(12):
                writer.writerow(
                    [f"https://docs{index}.example.com/page{index}", "benign"]
                )
                writer.writerow(
                    [
                        f"http://secure-login-{index}.invalid/login?verify={index}",
                        "phishing",
                    ]
                )

    def test_train_save_load_and_predict(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "urls.csv"
            artifact = Path(directory) / "url_model.joblib"
            self._write_dataset(dataset)

            report = train_model(dataset, artifact, random_state=7)
            prediction = predict_url(
                "http://secure-login-40.invalid/login?verify=40", artifact
            )

            self.assertTrue(artifact.is_file())
            self.assertEqual(report["training_samples"], 24)
            self.assertGreater(report["holdout_metrics"]["test_samples"], 0)
            self.assertIn("f1", report["holdout_metrics"])
            self.assertEqual(
                report["holdout_metrics"]["evaluation_split"],
                "host-separated holdout",
            )
            self.assertEqual(
                report["holdout_metrics"]["train_hosts"]
                + report["holdout_metrics"]["test_hosts"],
                24,
            )
            self.assertIn("score", prediction)
            self.assertIn("Uncalibrated", prediction["score_description"])

    def test_conflicting_duplicate_labels_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = Path(directory) / "urls.csv"
            dataset.write_text(
                "url,label\nhttps://example.com,benign\nhttps://example.com,phishing\n"
                "https://other.example,benign\nhttp://bad.invalid,phishing\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "conflicting labels"):
                train_model(dataset, Path(directory) / "model.joblib")

    def test_host_grouped_holdout_keeps_hosts_separate(self):
        labels = [0, 0, 1, 1, 0, 1, 0, 1]
        hosts = [
            "shared.example.com",
            "shared.example.com",
            "phish-a.invalid",
            "phish-b.invalid",
            "benign-a.example",
            "phish-c.invalid",
            "benign-b.example",
            "phish-d.invalid",
        ]
        train_indices, test_indices = _group_holdout(labels, hosts, 0.25, 12)

        self.assertFalse(
            set(hosts[index] for index in train_indices)
            & set(hosts[index] for index in test_indices)
        )
        self.assertEqual({labels[index] for index in train_indices}, {0, 1})
        self.assertEqual({labels[index] for index in test_indices}, {0, 1})


if __name__ == "__main__":
    unittest.main()
