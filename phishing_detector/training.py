"""Train and use a local scikit-learn URL classifier."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
from sklearn.model_selection import GroupShuffleSplit

from .features import FEATURE_NAMES, URLAnalysis, analyze_url
from .model import create_url_classifier

ARTIFACT_VERSION = 1
DEFAULT_ARTIFACT = Path(__file__).resolve().parent.parent / "models" / "url_model.joblib"
PHISHING_LABELS = frozenset({"phishing", "malicious"})
BENIGN_LABELS = frozenset({"benign", "legitimate", "safe"})


def _read_dataset(
    csv_path: Path,
    url_column: str,
    label_column: str,
    phishing_label: str,
    benign_label: str,
) -> tuple[list[list[float]], list[int], list[str], int, str]:
    if not phishing_label or not benign_label or phishing_label.lower() == benign_label.lower():
        raise ValueError("Phishing and benign label values must be distinct and non-empty.")
    digest_builder = hashlib.sha256()
    with csv_path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest_builder.update(chunk)
    digest = digest_builder.hexdigest()
    features: list[list[float]] = []
    labels: list[int] = []
    host_groups: list[str] = []
    seen: dict[str, int] = {}
    duplicate_rows_ignored = 0

    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames is None:
                raise ValueError("Dataset is empty or missing its CSV header.")
            missing_columns = {url_column, label_column}.difference(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    "Dataset is missing required column(s): " + ", ".join(sorted(missing_columns))
                )
            if url_column == label_column:
                raise ValueError("URL and label columns must be different.")

            for row in reader:
                line_number = reader.line_num
                raw_url = (row.get(url_column) or "").strip()
                raw_label = (row.get(label_column) or "").strip().lower()
                if not raw_url:
                    raise ValueError(f"CSV row {line_number} has an empty URL.")
                if raw_label == phishing_label.lower() or raw_label in PHISHING_LABELS:
                    label = 1
                elif raw_label == benign_label.lower() or raw_label in BENIGN_LABELS:
                    label = 0
                else:
                    raise ValueError(
                        f"CSV row {line_number} has unsupported label {raw_label!r}; "
                        f"use {phishing_label!r} for phishing and {benign_label!r} for benign."
                    )
                try:
                    analysis = analyze_url(raw_url)
                except ValueError as error:
                    raise ValueError(f"CSV row {line_number} has an invalid URL: {error}") from error

                normalized_url = analysis.normalized_url
                previous_label = seen.get(normalized_url)
                if previous_label is not None:
                    if previous_label != label:
                        raise ValueError(
                            f"CSV row {line_number} assigns conflicting labels to duplicate URL "
                            f"{normalized_url!r}."
                        )
                    duplicate_rows_ignored += 1
                    continue
                seen[normalized_url] = label
                features.append(analysis.as_vector())
                labels.append(label)
                host_groups.append(analysis.hostname)
    except UnicodeDecodeError as error:
        raise ValueError("Dataset must be a UTF-8 encoded CSV file.") from error

    if not features:
        raise ValueError("Dataset contains no labeled URLs.")
    if set(labels) != {0, 1}:
        raise ValueError("Dataset must contain both phishing and benign examples.")
    if min(labels.count(0), labels.count(1)) < 2:
        raise ValueError("Dataset needs at least two distinct URLs from each class.")
    return features, labels, host_groups, duplicate_rows_ignored, digest


def train_model(
    csv_path: str | Path,
    artifact_path: str | Path = DEFAULT_ARTIFACT,
    *,
    url_column: str = "url",
    label_column: str = "label",
    phishing_label: str = "1",
    benign_label: str = "0",
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict[str, Any]:
    """Evaluate a holdout split, then save a classifier fitted on all labeled data."""
    if not 0 < test_size < 1:
        raise ValueError("Test size must be greater than 0 and less than 1.")
    dataset_path = Path(csv_path)
    features, labels, host_groups, duplicate_rows_ignored, dataset_sha256 = _read_dataset(
        dataset_path,
        url_column,
        label_column,
        phishing_label,
        benign_label,
    )
    split = _group_holdout(labels, host_groups, test_size, random_state)
    train_indices, test_indices = split
    train_features = [features[index] for index in train_indices]
    test_features = [features[index] for index in test_indices]
    train_labels = [labels[index] for index in train_indices]
    test_labels = [labels[index] for index in test_indices]
    train_hosts = {host_groups[index] for index in train_indices}
    test_hosts = {host_groups[index] for index in test_indices}

    evaluation_model = create_url_classifier(random_state)
    evaluation_model.fit(train_features, train_labels)
    predictions = evaluation_model.predict(test_features).tolist()
    metrics = {
        "accuracy": float(accuracy_score(test_labels, predictions)),
        "precision": float(precision_score(test_labels, predictions, zero_division=0)),
        "recall": float(recall_score(test_labels, predictions, zero_division=0)),
        "f1": float(f1_score(test_labels, predictions, zero_division=0)),
        "confusion_matrix_labels_0_1": confusion_matrix(
            test_labels, predictions, labels=[0, 1]
        ).tolist(),
        "test_samples": len(test_labels),
        "evaluation_split": "host-separated holdout",
        "train_hosts": len(train_hosts),
        "test_hosts": len(test_hosts),
    }

    final_model = create_url_classifier(random_state)
    final_model.fit(features, labels)
    artifact = {
        "format": "linklens-sklearn-url-classifier",
        "version": ARTIFACT_VERSION,
        "algorithm": "random_forest",
        "feature_names": list(FEATURE_NAMES),
        "model": final_model,
        "training_samples": len(labels),
        "dataset_sha256": dataset_sha256,
        "holdout_metrics": metrics,
    }
    output_path = Path(artifact_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)

    return {
        "artifact": str(output_path.resolve()),
        "training_samples": len(labels),
        "duplicate_rows_ignored": duplicate_rows_ignored,
        "holdout_metrics": metrics,
        "dataset_sha256": dataset_sha256,
    }


def _group_holdout(
    labels: list[int],
    groups: list[str],
    test_size: float,
    random_state: int,
) -> tuple[list[int], list[int]]:
    """Choose a reproducible host-separated split containing both label classes."""
    splitter = GroupShuffleSplit(
        n_splits=100,
        test_size=test_size,
        random_state=random_state,
    )
    for train_indices, test_indices in splitter.split(
        X=[0] * len(labels), y=labels, groups=groups
    ):
        if (
            set(labels[index] for index in train_indices) == {0, 1}
            and set(labels[index] for index in test_indices) == {0, 1}
        ):
            return train_indices.tolist(), test_indices.tolist()
    raise ValueError(
        "Could not create a host-separated holdout containing both classes. "
        "Add more labeled hosts per class or adjust --test-size."
    )


def load_model_artifact(artifact_path: str | Path = DEFAULT_ARTIFACT) -> dict[str, Any]:
    """Load a LinkLens artifact; only load artifacts you created or trust."""
    path = Path(artifact_path)
    if not path.is_file():
        raise FileNotFoundError(f"Trained model not found: {path}")
    artifact = joblib.load(path)
    if (
        not isinstance(artifact, dict)
        or artifact.get("format") != "linklens-sklearn-url-classifier"
        or artifact.get("version") != ARTIFACT_VERSION
        or artifact.get("algorithm") != "random_forest"
        or artifact.get("feature_names") != list(FEATURE_NAMES)
        or not isinstance(artifact.get("model"), RandomForestClassifier)
        or list(artifact["model"].classes_) != [0, 1]
        or artifact["model"].n_features_in_ != len(FEATURE_NAMES)
    ):
        raise ValueError("Model artifact is invalid or incompatible with this feature schema.")
    return artifact


def predict_url(value: str, artifact_path: str | Path = DEFAULT_ARTIFACT) -> dict[str, object]:
    """Return an uncalibrated model score for a single URL."""
    artifact = load_model_artifact(artifact_path)
    analysis = analyze_url(value)
    return predict_analysis(analysis, artifact)


def predict_analysis(analysis: URLAnalysis, artifact: dict[str, Any]) -> dict[str, object]:
    """Score an already-extracted URL analysis using a validated model artifact."""
    model = artifact["model"]
    probabilities = model.predict_proba([analysis.as_vector()])[0]
    phishing_index = list(model.classes_).index(1)
    score = round(float(probabilities[phishing_index]) * 100)
    return {
        "url": analysis.normalized_url,
        "hostname": analysis.hostname,
        "score": score,
        "label": "phishing-pattern" if score >= 50 else "benign-pattern",
        "score_description": (
            "Uncalibrated model score, not a probability or a safety guarantee."
        ),
        "training_samples": artifact["training_samples"],
        "holdout_metrics": artifact["holdout_metrics"],
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Train and evaluate LinkLens using a labeled CSV of URLs."
    )
    parser.add_argument("--input", required=True, help="CSV file with URL and label columns.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_ARTIFACT),
        help=f"Model artifact output path (default: {DEFAULT_ARTIFACT}).",
    )
    parser.add_argument("--url-column", default="url", help="URL column name (default: url).")
    parser.add_argument(
        "--label-column", default="label", help="Label column name (default: label)."
    )
    parser.add_argument(
        "--phishing-label",
        default="1",
        help="Label value representing phishing (default: 1).",
    )
    parser.add_argument(
        "--benign-label",
        default="0",
        help="Label value representing benign (default: 0).",
    )
    parser.add_argument(
        "--test-size", type=float, default=0.2, help="Stratified holdout fraction (default: 0.2)."
    )
    parser.add_argument("--random-state", type=int, default=42, help="Split/model seed.")
    args = parser.parse_args()
    try:
        report = train_model(
            args.input,
            args.output,
            url_column=args.url_column,
            label_column=args.label_column,
            phishing_label=args.phishing_label,
            benign_label=args.benign_label,
            test_size=args.test_size,
            random_state=args.random_state,
        )
    except (OSError, csv.Error, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
