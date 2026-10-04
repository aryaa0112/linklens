# LinkLens

**Look closer. Click smarter.** LinkLens is a privacy-first phishing URL risk
screener that pairs transparent URL heuristics with a trained machine-learning
model. It explains the signals behind its assessments instead of presenting
an unexplained verdict.

> LinkLens is an educational risk-screening tool, not a security guarantee.
> Neither a low score nor HTTPS proves that a website is safe.

## Highlights

- **Two independent perspectives:** an explainable heuristic score and a
  Random Forest model score appear together in a single-link scan.
- **Disagreement guidance:** the dashboard calls out when the two approaches
  differ and recommends treating uncertain links cautiously.
- **Readable evidence:** heuristic findings include descriptions and point
  contributions; model scores are explicitly identified as uncalibrated.
- **Batch workflow:** screen up to 100 pasted URLs and export a CSV summary.
- **Local-by-default:** the app binds to `127.0.0.1`; submitted links are
  analyzed as text and are never opened or fetched.
- **Reproducible training:** train from a labeled CSV with hostname-separated
  evaluation, duplicate checks, a dataset hash, and standard classification
  metrics.

## Run locally

Use Python 3.10 or later. From the project directory:

```powershell
python -m pip install -r requirements.txt
python -m phishing_detector
```

Open <http://127.0.0.1:8765>. To choose another port, run
`python -m phishing_detector --port 9000`. Stop the server with Ctrl+C.

The checked-in model is at [`models/url_model.joblib`](models/url_model.joblib).
If it is missing, the heuristic scan still works and the UI explains that the
model is unavailable.

## How it works

1. The URL parser validates an HTTP(S) URL or a domain and extracts lexical
   signals without resolving DNS or requesting the destination.
2. The heuristic scorer produces a capped 0–100 pattern-risk score with
   human-readable findings.
3. The Random Forest model evaluates the same ordered URL feature vector and
   returns its class score. This score is **not a calibrated probability**.
4. The dashboard presents both results and a cautious interpretation if they
   disagree.

LinkLens does not inspect page contents, follow redirects, check live
reputation feeds, verify certificates, or establish that a destination is
benign.

## Model and evaluation

The checked-in artifact was trained from the UCI
[PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset).
UCI reports 134,850 legitimate and 100,945 phishing examples and lists the
dataset under CC BY 4.0. Dataset citation:

> Prasad, A., & Chandra, S. (2023). “PhiUSIIL: A diverse security profile
> empowered phishing URL detection framework based on similarity index and
> incremental learning.” *Computers & Security*, 103545.
> <https://doi.org/10.1016/j.cose.2023.103545>

The downloaded CSV is not included in this repository. To retrain, download it
and run:

```powershell
New-Item -ItemType Directory -Force data | Out-Null
curl.exe --fail --location --output data\phiusiil.csv https://archive.ics.uci.edu/static/public/967/data.csv
python -m phishing_detector.training --input data\phiusiil.csv --url-column URL --label-column label --phishing-label 0 --benign-label 1
```

For this dataset, label `0` means phishing and `1` means legitimate. The
training command saves `models/url_model.joblib` and prints a SHA-256 dataset
hash, holdout accuracy, precision, recall, F1, and confusion matrix.

The recorded hostname-separated holdout used 47,511 URLs and reported:

| Metric | Result |
|---|---:|
| Accuracy | 0.9960 |
| Precision | 0.9986 |
| Recall | 0.9920 |
| F1 | 0.9953 |

These are results on this dataset and feature set, not expected performance on
new URLs in the wild. URLs sharing a hostname are kept together across train
and holdout sets, but related parent domains or campaigns can still occur on
both sides. LinkLens trains on URL text only, not the dataset's webpage-derived
fields.

For another CSV, use columns named `url` and `label` with labels
`phishing`/`benign` or `1`/`0`. Customize `--url-column`, `--label-column`,
`--phishing-label`, and `--benign-label` as needed. Duplicate normalized URLs
are removed; conflicting labels are rejected. Both classes and enough
distinct hostnames must be present in the train and holdout splits.

Only load model artifacts you trained or otherwise trust: joblib artifacts can
execute code when loaded. Use the same compatible scikit-learn environment
between training and inference.

## API

The local dashboard provides JSON endpoints:

- `POST /api/analyze` with `{"url":"https://example.com"}` returns the
  heuristic assessment and the ML assessment when a trained model is present.
- `POST /api/batch` with `{"urls":["https://example.com"]}` analyzes up to 100
  URLs using the heuristic scorer.
- `POST /api/predict` with `{"url":"https://example.com"}` returns the ML
  assessment directly.

## Tests

```powershell
python -m unittest discover -s tests -v
```

