"""A compact Gaussian Naive Bayes classifier implemented with the stdlib."""

from __future__ import annotations

import math

from sklearn.ensemble import RandomForestClassifier


def create_url_classifier(random_state: int = 42) -> RandomForestClassifier:
    """Create the scikit-learn classifier used by the labeled-data workflow."""
    return RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=1,
    )


class GaussianNaiveBayes:
    """Gaussian Naive Bayes for fixed-width numeric feature vectors."""

    classes_ = [0, 1]

    def __init__(self) -> None:
        self.means: list[list[float]] = []
        self.variances: list[list[float]] = []
        self.priors: list[float] = []

    def fit(self, features: list[list[float]], labels: list[int]) -> GaussianNaiveBayes:
        if not features or len(features) != len(labels):
            raise ValueError("Features and labels must contain the same non-zero number of rows.")
        width = len(features[0])
        if width == 0 or any(len(row) != width for row in features):
            raise ValueError("Every feature row must have the same non-zero width.")
        if set(labels) != {0, 1}:
            raise ValueError("Training data must contain both class labels 0 and 1.")

        for row in features:
            if any(not math.isfinite(value) for value in row):
                raise ValueError("Feature values must be finite numbers.")

        global_means = [sum(row[index] for row in features) / len(features) for index in range(width)]
        global_variances = [
            sum((row[index] - global_means[index]) ** 2 for row in features) / len(features)
            for index in range(width)
        ]
        smoothing = [max(variance, 1.0) * 1e-9 for variance in global_variances]

        self.means = []
        self.variances = []
        self.priors = []
        for label in self.classes_:
            rows = [row for row, row_label in zip(features, labels) if row_label == label]
            class_means = [sum(row[index] for row in rows) / len(rows) for index in range(width)]
            class_variances = [
                sum((row[index] - class_means[index]) ** 2 for row in rows) / len(rows) + smoothing[index]
                for index in range(width)
            ]
            self.means.append(class_means)
            self.variances.append(class_variances)
            self.priors.append(len(rows) / len(features))
        return self

    def predict_proba(self, features: list[list[float]]) -> list[list[float]]:
        if not self.means or not self.variances or not self.priors:
            raise ValueError("Fit the classifier before requesting predictions.")

        predictions = []
        for row in features:
            if len(row) != len(self.means[0]):
                raise ValueError("Prediction feature width does not match the trained model.")
            log_likelihoods = []
            for class_index in range(len(self.classes_)):
                log_probability = math.log(self.priors[class_index])
                for index, value in enumerate(row):
                    variance = self.variances[class_index][index]
                    difference = value - self.means[class_index][index]
                    log_probability -= 0.5 * (
                        math.log(2 * math.pi * variance) + difference * difference / variance
                    )
                log_likelihoods.append(log_probability)

            maximum = max(log_likelihoods)
            likelihoods = [math.exp(value - maximum) for value in log_likelihoods]
            total = sum(likelihoods)
            predictions.append([value / total for value in likelihoods])
        return predictions

    def to_dict(self) -> dict[str, object]:
        if not self.means or not self.variances or not self.priors:
            raise ValueError("Fit the classifier before saving it.")
        return {
            "algorithm": "gaussian_naive_bayes",
            "classes": self.classes_,
            "means": self.means,
            "variances": self.variances,
            "priors": self.priors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> GaussianNaiveBayes:
        if data.get("algorithm") != "gaussian_naive_bayes" or data.get("classes") != [0, 1]:
            raise ValueError("Model artifact is not a supported Gaussian Naive Bayes model.")
        model = cls()
        try:
            model.means = [[float(value) for value in row] for row in data["means"]]
            model.variances = [[float(value) for value in row] for row in data["variances"]]
            model.priors = [float(value) for value in data["priors"]]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Model artifact contains invalid parameters.") from error

        if (
            len(model.means) != 2
            or len(model.variances) != 2
            or len(model.priors) != 2
            or not model.means[0]
            or any(len(row) != len(model.means[0]) for row in model.means + model.variances)
            or any(value <= 0 or not math.isfinite(value) for row in model.variances for value in row)
            or any(value <= 0 or not math.isfinite(value) for value in model.priors)
        ):
            raise ValueError("Model artifact has inconsistent or invalid parameter dimensions.")
        if not math.isclose(sum(model.priors), 1.0, rel_tol=1e-6):
            raise ValueError("Model artifact class priors must sum to 1.")
        return model