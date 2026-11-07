# PhishShield — Vercel edition

This branch adds a Next.js interface and Python API while retaining the existing URL feature extraction code in `src/features.py`.

## Architecture

- Next.js App Router UI at `/`
- FastAPI Python function at `/api`
- `POST /api/analyze` checks one URL
- `POST /api/scan-csv` scans CSV text (up to 500 rows / 2 MB)
- The API parses URL text only and never visits submitted destinations.
- If `models/phishing_model.joblib` is present, the API attempts model inference; otherwise it clearly reports heuristic demo mode.

## Deploy

1. Import `abhinavprasadsingh/PhishShield` into Vercel.
2. Select the `vercel-migration` branch.
3. Keep the project root as `./`; use the Next.js framework preset.
4. Deploy. Vercel reads `pyproject.toml` for Python API dependencies and `package.json` for Next.js.
5. Verify `/api/health`, URL analysis, and CSV upload.

The existing `requirements.txt`, `render.yaml`, and Streamlit app are deliberately retained so the Render deployment is not changed by this migration branch.

## Local development

Use Python 3.12 and Node.js 20.9 or newer:

```powershell
npm install
python -m pip install fastapi pandas numpy scikit-learn joblib
npm run dev
```

The local Next.js dev server does not automatically run the Python function. Use Vercel CLI (`npm i -g vercel`, then `vercel dev`) to test the integrated frontend and Python API locally.

## Limitations

- The model artifact is gitignored and is not present in the repository by default. Without it, heuristic demo mode is used.
- CSV scanning is request-scoped and capped at 500 rows.
- No persistent scan history or database is configured.
- Heuristic scores are not calibrated probabilities and a low score is not a safety guarantee.
