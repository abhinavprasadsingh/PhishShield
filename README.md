# PhishShield — Intelligent Phishing Detection 🛡️

PhishShield is a Python-based project that analyzes URL patterns to identify potentially suspicious links, with a Streamlit interface and machine learning model training and evaluation.

> **Current project status:** The Streamlit app supports explainable heuristic demo mode and can load a trained model from `models/phishing_model.joblib` when that file is present. A supervised training run has completed in GitHub Actions using UCI PhiUSIIL dataset 967; the trained model and evaluation logs are available as a temporary Actions artifact (30-day retention). The model artifact is not committed to this repository, so do not assume the public app is currently serving this trained model.

## Why this matters

Fake banking links, delivery notifications, login pages, and fraudulent offers can be designed to steal credentials. PhishShield helps users inspect suspicious URL patterns before deciding what to do next. It is a decision-support tool, not a replacement for browser protection or a professional security review.

## Features

- Premium dark Streamlit interface
- URL parsing and feature extraction without visiting the submitted URL
- Explainable heuristic demo mode when no trained model is available
- Optional scikit-learn model loaded from `models/phishing_model.joblib`
- Shows extracted features and human-readable warning signals
- Training pipeline compares Logistic Regression, Random Forest, and HistGradientBoosting
- Evaluation reporting for accuracy, precision, recall, F1, average precision (PR-AUC), and a confusion matrix
- Automated tests and GitHub Actions checks

## Tech stack

- **Python** for application and analysis
- **Pandas** for tabular feature inputs and dataset handling
- **scikit-learn** for supervised classification and evaluation
- **Streamlit** for the interactive web demo
- **HTML/CSS** for interface styling
- **SQLite** is a possible future addition for local scan history; it is not currently required by the core app.

## Dataset and supervised training

The reproducible workflow uses the [UCI PhiUSIIL Phishing URL dataset (ID 967)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset). It exports only URL text and labels, maps them to this project’s convention (`0` = legitimate, `1` = phishing), and does not visit destination URLs. Dataset attribution, evaluation methodology, measured results, and limitations are documented in [reports/evaluation.md](reports/evaluation.md).

Prepare a CSV with two columns:
- `url`: URL text
- `label`: `1` for phishing, `0` for legitimate

Keep raw data out of Git (for example, `data/urls.csv`) and never open URLs from the dataset. Avoid training/test leakage by separating related domains where feasible and documenting the split.

## Run locally (Windows PowerShell)

1. Install Python 3.11 or newer from https://www.python.org/downloads/.
2. Open PowerShell in the project folder.
3. Create an environment, install dependencies, and launch Streamlit:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit prints a local address, usually http://localhost:8501.

## Deploy on Render

PhishShield keeps its Streamlit interface and runs as a Render Web Service. The repository includes a Render Blueprint (`render.yaml`) and a pinned Python runtime (`.python-version`).

### Deploy with Render Blueprint

1. Sign in to [Render](https://dashboard.render.com/).
2. Connect your GitHub account to Render if it is not connected already.
3. Open [New + → Blueprint](https://dashboard.render.com/blueprints) and select this repository: `abhinavprasadsingh/PhishShield`.
4. Select branch `main`. Render reads `render.yaml` and configures the service.
5. Review the service and choose the Free plan, then create the Blueprint.
6. Wait for the build and deploy to finish. Open the generated `*.onrender.com` URL and test valid and invalid URLs, CSV scanning, and the dashboard.

The service binds Streamlit to Render's `0.0.0.0` host and the port supplied in the `PORT` environment variable. Render's health check uses Streamlit's `/_stcore/health` endpoint. The app reads Render's `RENDER_EXTERNAL_URL` for analytics page location; no API key is required for hosting.

### Important deployment notes

- A GitHub push triggers a new deploy when automatic deploys are enabled for the linked `main` branch. A successful push alone does not prove that the live deployment succeeded.
- Render Free web services spin down after 15 minutes without inbound traffic and can take time to wake on the next visit.
- The scan history is session-only and is not persisted in a database. Uploaded files and generated files on an ephemeral service filesystem should not be treated as permanent storage.
- The trained model file `models/phishing_model.joblib` is not committed by default. Unless you add the artifact through a secure, reproducible deployment process, the app will use heuristic demo mode.
- The previous Streamlit Community Cloud deployment is not automatically deleted. Keep it until the Render deployment has been tested, then you can optionally retire it.

## Train a supervised model (optional)

To reproduce training locally, first prepare the UCI dataset:

```powershell
pip install ucimlrepo
python scripts/prepare_uci_dataset.py
python -m src.train --input data/urls.csv --output models/phishing_model.joblib
```

The latest successful [GitHub Actions training run](https://github.com/abhinavprasadsingh/PhishShield/actions/runs/38618944295) compares three classifiers and uploads the model plus logs as an artifact. See [measured results and caveats](reports/evaluation.md).

The training script removes exact duplicate URLs, compares Logistic Regression, Random Forest, and HistGradientBoosting, reports evaluation metrics, and saves the selected model to `models/phishing_model.joblib`. Review [the evaluation notes](reports/evaluation.md). Metrics depend on dataset quality, label reliability, and split design; do not claim performance without running and documenting the experiment.

## Tests

```powershell
python -m compileall -q app.py src tests
pytest -q
```

GitHub Actions runs these checks on pushes and pull requests.

## Viva explanation

“The system extracts measurable features from a URL and can use a classifier trained on labeled phishing and legitimate examples to estimate its class. It also shows understandable warning signals so users can inspect why a URL deserves caution. A prediction is not a guarantee of safety.”

## Limitations and safe use

- Heuristic demo scores are **not** machine-learning predictions or calibrated probabilities.
- URL features alone can miss sophisticated phishing and can flag legitimate URLs.
- HTTPS does not prove that a website is legitimate.
- A low-risk result is not a safety guarantee.
- The app parses the submitted URL as text; it does not visit it, follow redirects, or fetch page content.
- Avoid submitting URLs that contain private access tokens, session IDs, or personal data.

## Project structure

```text
PhishGuard-AI/
├── app.py
├── requirements.txt
├── src/
│   ├── features.py
│   └── train.py
├── tests/
├── data/README.md
├── models/README.md
├── reports/evaluation.md
├── docs/VIVA.md
└── .github/workflows/tests.yml
```

## License

MIT. See [LICENSE](LICENSE).
