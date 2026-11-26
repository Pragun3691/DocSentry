# DocSentry: Explainable, Uncertainty-Aware PDF Malware Detector

**DocSentry** is an end-to-end, production-grade PDF malware detection engine developed for university research, built upon static features extracted from the EMBER2024 benchmark subset ([FutureComputing4AI/EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)).

DocSentry emphasizes:
1. **No execution: the file is never opened, rendered or run**: Pure static analysis on raw byte distributions, entropy structures, and printable strings. Files are never opened, rendered, or executed.
2. **Selective Review Band Triage**: An isotonic probability calibrator combined with an uncertainty review band ($[0.290, 0.550]$) routes borderline, high-uncertainty documents to manual human triage, preventing automated false alarms.
3. **Transparent Explainability**: Local SHAP (TreeExplainer) explanations provide exact directional attribution for every decision, with technical feature names automatically decoded into plain English.
4. **Out-of-Distribution (OOD) Protection**: Detects documents whose file size or string count deviates beyond the training set's 0.5%–99.5% envelope.

---

## Folder Structure

```
DocSentry/
├── app/                            # Local production web application
│   ├── main.py                     # FastAPI backend (security checks, REST API)
│   └── static/                     # Single-page interface (pure HTML/CSS/JS, zero CDNs)
│       ├── fonts/                  # Self-hosted WOFF2 fonts + LICENSES.md (OFL-1.1)
│       ├── index.html              # Responsive single-page layout
│       ├── style.css               # Paper & mono light/dark theme stylesheets
│       └── app.js                  # Vanilla JS frontend, SVG charts, session history
├── data/
│   ├── raw/                        # Git-ignored: raw EMBER2024 JSONL subset (64 weeks)
│   ├── processed/                  # Git-ignored: Parquet datasets; feature_names.json is tracked
│   └── demo_pdfs/
│       ├── synthetic/              # Harmless pure-Python synthetic PDF test suite
│       └── user/                   # Git-ignored: private user evaluation documents
├── models/                         # Serialized models and operational artifacts
│   ├── ablation/                   # Retrained XGBoost ablation models (Notebook 08)
│   ├── best_model.joblib           # Champion tuned XGBoost model
│   ├── calibrator.joblib           # Fitted IsotonicRegression calibrator
│   └── thresholds.json             # Operating threshold, review band, and OOD bounds
├── notebooks/                      # Research and audit notebooks (01 to 08)
│   ├── 01_data_understanding.ipynb
│   ├── 02_eda.ipynb
│   ├── 03_preprocessing.ipynb
│   ├── 04_modeling.ipynb
│   ├── 05_explain_uncertainty.ipynb
│   ├── 06_real_pdf_demo.ipynb
│   ├── 07_demo_diagnostics.ipynb
│   └── 08_uri_counterfactual.ipynb
├── report_assets/                  # Curated figures, CSVs, and index.md for reporting
├── reports/                        # Metrics, CSV summaries, and figures
│   ├── figures/                    # Saved figures (01 to 41, plus UI screenshots)
│   ├── model_comparison.csv        # Multi-model test benchmark metrics
│   └── demo_scan_results.csv       # Batch scan output for synthetic demo suite
├── scripts/                        # Utility CLI scripts
│   ├── generate_synthetic_pdfs.py  # Pure-Python synthetic PDF generator
│   ├── make_report_assets.py       # Bundles report_assets/ from reports/
│   └── scan_pdfs.py                # Batch directory scanner utility
├── src/                            # Production Python library
│   ├── docsentry_extract.py        # Static feature extraction pipeline
│   └── docsentry_infer.py          # Calibrated inference, SHAP, and OOD engine
├── tests/                          # Automated unit test suite
│   ├── test_extract.py             # Pipeline fidelity tests (requires data/processed/*.parquet)
│   ├── test_infer.py               # Model & calibrator tests (requires data/processed/*.parquet)
│   └── test_api.py                 # FastAPI TestClient & scan tests (runs out of the box)
├── MODEL_CARD.md                   # Model specifications, CIs, limitations, and domain-shift audit
├── PROGRESS.md                     # Comprehensive research and progress log
├── requirements.txt                # Exact pinned dependencies
└── run_app.bat                     # Windows one-click launcher
```

---

## Setup & Installation

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Windows / macOS / Linux

### 2. Environment Setup
```bash
# Clone or navigate to the repository
cd DocSentry

# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (cmd/PowerShell):
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install exact requirements
pip install -r requirements.txt
```

---

## Running the Web Application

To launch the local web interface and API server:

### Option A: Windows One-Click Launcher
Double-click `run_app.bat` or run:
```cmd
run_app.bat
```

### Option B: Command Line (Uvicorn)
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Once running:
- **Interactive Web UI**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## Scanning a Folder of PDFs via CLI

To batch-scan a folder of PDF documents and export CSV results:
```bash
python scripts/scan_pdfs.py --folder data/demo_pdfs/user --output reports/user_scan_results.csv
```

Arguments:
- `--folder`: Target directory containing `.pdf` files.
- `--output`: Destination CSV path (defaults to `reports/demo_scan_results.csv`).
- `--models-dir`: Directory containing model artifacts (default: `models`).
- `--processed-dir`: Directory containing feature metadata (default: `data/processed`).

---

## Full Reproducibility Guide

Follow these steps in order to reproduce the entire DocSentry pipeline from raw data to the running web application:

### 1. Download EMBER2024 PDF Subset (Optional for Inference; Required for Notebooks 01–05 & 08)
Raw EMBER2024 JSONL files (`data/raw/`) and processed Parquet files (`data/processed/*.parquet`) are git-ignored. The web app, CLI scanner, and `tests/test_api.py` run immediately from a fresh clone using the tracked `models/` and `data/processed/feature_names.json` artifacts.

To reproduce the dataset and training notebooks from scratch, ensure `requirements.txt` is installed (including `signify==0.7.1`, pinned for `thrember` compatibility), then download only the PDF subset into `data/raw/`:
```python
import thrember
thrember.download_dataset("data/raw", file_type="PDF")
```

### 2. Execute Research Notebooks in Order (`01` to `08`)
Run the notebooks sequentially so each stage's Parquet outputs (`data/processed/*.parquet`), models, and calibration artifacts are generated for the next stage:
1. `notebooks/01_data_understanding.ipynb` — Inspects raw weekly `.jsonl` partitions and schema.
2. `notebooks/02_eda.ipynb` — SHA-256 deduplication and exploratory univariate/bivariate analysis.
3. `notebooks/03_preprocessing.ipynb` — Temporal 42/10/12-week split, constant-feature pruning (696 → 658), log1p/scaling, and adversarial drift checks.
4. `notebooks/04_modeling.ipynb` — Trains & tunes Logistic Regression, Random Forest, XGBoost, and HistGradientBoosting; exports `models/best_model.joblib` and `reports/best_params.json`.
5. `notebooks/05_explain_uncertainty.ipynb` — Fits Isotonic Regression calibrator, optimizes review band `[0.290, 0.550]`, runs bootstrap CIs, size-matched & `/URI` dependence audits, and computes SHAP explanations.
6. `notebooks/06_real_pdf_demo.ipynb` — Runs end-to-end static extraction & inference on synthetic demo PDFs.
7. `notebooks/07_demo_diagnostics.ipynb` — Audits the isotonic calibration plateau and establishes OOD percentile bounds.
8. `notebooks/08_uri_counterfactual.ipynb` — Runs `/URI` counterfactual dose-response curves, feature ablations, and domain-shift percentile checks.

### 3. Run Automated Unit Tests
- **Fresh clone (no dataset download required, 11 tests):**
```bash
python -m unittest tests/test_api.py -v
```
- **Full suite (19 tests; `test_extract.py` and `test_infer.py` require `data/processed/X_test_tree.parquet` generated by Notebooks 01–03):**
```bash
python -m unittest discover tests -v
```

### 4. Start the Web Application
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
See [MODEL_CARD.md](MODEL_CARD.md) for complete model specifications, metrics, confidence intervals, and ethical disclosures. To bundle all final figures and CSVs for reporting, run `python scripts/make_report_assets.py`.

> **Demo note:** All six `synthetic_*.pdf` files are harmless by construction. `synthetic_a`, `synthetic_b`, and `synthetic_c` are flagged or sent to review primarily by low extracted string counts (`+0.63` to `+0.86` SHAP) and byte-histogram anomalies (`0x49` `+0.37` to `+0.43`) despite having zero links; `synthetic_f` has a low raw score (`0.2080`) driven toward benign by its size, string count, and zero links, but lands on the calibrator's `0.4082` `needs_review` plateau (along with `synthetic_a` and `user_pdf_8`). Only `synthetic_d` (`/URI` `+1.64`, `https://` `+0.43`) and `synthetic_e` (`javascript` `+1.88`) are flagged for link counts or script keywords.

---

## Benchmark Performance Highlights (EMBER2024 Test Set, 12,000 Documents)

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **XGBoost (Champion)** | **94.75%** | **98.996%** | **90.42%** | **0.9451** | **0.9887** | **0.9911** | **0.92%** |
| HistGradientBoosting | 95.02% | 99.23% | 90.73% | 0.9479 | 0.9889 | 0.9914 | 0.70% |
| Random Forest | 93.53% | 99.17% | 87.78% | 0.9313 | 0.9879 | 0.9903 | 0.73% |
| Logistic Regression | 94.45% | 97.81% | 90.93% | 0.9425 | 0.9765 | 0.9803 | 2.03% |

- **Operating Decision Threshold**: $t = 0.4083$ on calibrated probability.
- **Selective Review Band**: $[0.290, 0.550]$ achieves **97.24%** auto-decision accuracy on the test set while escalating only **3.77%** of borderline documents.

---

## System Limitations & Honest Boundaries

1. **Static Analysis Boundary**: Pure static byte-level features cannot detect zero-day memory corruption shellcode executing inside clean-looking streams; DocSentry serves as a rapid pre-filter in a defense-in-depth posture alongside dynamic sandboxing.
2. **Link Indicator Dependence**: Approximately $19.36\%$ of total model attribution rests on `/URI` link indicators. Attackers can evade detection by omitting `/URI`, while benign documents with extensive hyperlinks risk false alarms.
3. **Small Benign File Penalty**: Benign files under 100 KB experience a higher false positive rate ($5.65\%$ vs $0.25\%$ for $\ge 100$ KB) due to the EMBER2024 dataset's size-class imbalance.
4. **Not an Antivirus Replacement**: DocSentry classifies structural risk probability and provides feature attributions; it does not replace signature-based AV or endpoint protection agents.
5. **No CVE Exploit Identification**: The model provides threat probabilities and feature importance, but does not identify specific CVE numbers or exploit mechanics.
6. **Stepwise Isotonic Calibration Plateau**: Calibrated probabilities are generated by non-parametric isotonic regression (a monotonic step function). Raw model scores between 0.20 and 0.30 all map to a flat plateau at calibrated P = 0.4082 (40.8%), placing them directly into the $[0.290, 0.550]$ human review band.
