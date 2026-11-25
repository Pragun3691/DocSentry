# DocSentry Model Card

**Model**: DocSentry PDF Malware Classifier (`XGBoost` + `IsotonicRegression` Calibrator)  
**Task**: Static, explainable, uncertainty-aware binary triage (`benign`, `needs_review`, `malicious`) for PDF documents  
**Dataset**: EMBER2024 Benchmark PDF Subset  

---

## 1. Intended Use and Non-Use

### Intended Use
- **Rapid Pre-Filter & Triage Assistant**: Designed for security analysts and automated ingestion pipelines to quickly score incoming PDF files using pure static byte-level features without opening, rendering, or executing the file.
- **Uncertainty-Aware Escalation**: Routes borderline, high-uncertainty documents falling within the calibrated probability interval $[0.290, 0.550]$ to human review rather than forcing low-confidence automated verdicts.
- **Explainable Diagnostics**: Provides local SHAP feature attributions and plain-language summaries to assist human analysts during manual triage.

### Out-of-Scope / Non-Use
- **Not an Antivirus Replacement**: Must not be used as a standalone endpoint protection product or a substitute for signature-based AV and dynamic sandboxing.
- **Not Tested on Live Wild Malware**: All evaluation metrics are measured on the EMBER2024 benchmark subset; performance against novel, live zero-day exploits or adversarial evasion campaigns in the wild is unverified.
- **No Exploit / CVE Attribution**: The model classifies structural risk probability and does not identify specific CVEs, shellcode payloads, or software vulnerabilities.

---

## 2. Training & Evaluation Data

- **Source**: EMBER2024 PDF subset (`thrember` static feature extraction).
- **Deduplication**: SHA-256 deduplication across 64 weekly `.jsonl` partitions, plus removal of 1 TLSH near-duplicate overlap between training and validation (`data/processed/preprocessing_report.json`).
- **Temporal Split (42 / 10 / 12 Weeks)**:
  - **Train (Weeks 0–41)**: **42,000** documents (21,000 benign, 21,000 malicious)
  - **Validation (Weeks 42–51)**: **9,999** documents (5,000 benign, 4,999 malicious)
  - **Test (Weeks 52–63)**: **12,000** documents (6,000 benign, 6,000 malicious)
  - **Total Deduplicated Corpus**: **63,999** documents.
- **Feature Space**: **658** static numeric features (reduced from 696 raw features by dropping 38 constant/zero-variance features identified strictly on the training split).

---

## 3. Model Architecture & Selection

- **Selection Criterion**: Chosen among Logistic Regression, Random Forest, XGBoost, and HistGradientBoosting based on **Validation F1-Score** (`0.9824`, Validation Recall `0.9688`, Validation ROC-AUC `0.9977`).
- **Champion Hyperparameters** (`reports/best_params.json`):
  - `n_estimators`: `150`
  - `max_depth`: `5`
  - `learning_rate`: `0.05`
  - `subsample`: `0.9`
  - `colsample_bytree`: `0.7`
  - `tree_method`: `"hist"`
  - `random_state`: `42`
- **Calibration**: Non-parametric **Isotonic Regression** fitted on validation scores, selected over Sigmoid/Platt scaling via 5-fold cross-validation Brier score on the validation split (`0.012248` vs `0.013246`).

---

## 4. Quantitative Evaluation Metrics (Test Set, $N = 12,000$)

### Standard Unmatched Test Performance (`reports/model_comparison.csv`)
| Metric | XGBoost Value |
| :--- | :--- |
| **Accuracy** | 0.9475 (94.75%) |
| **Precision** | 0.9900 (99.00%) |
| **Recall** | 0.9042 (90.42%) |
| **F1-Score** | 0.9451 |
| **ROC-AUC** | 0.9887 |
| **PR-AUC** | 0.9911 |
| **False Positive Rate (FPR)** | 0.0092 (0.92%) |
| **False Negative Rate (FNR)** | 0.0958 (9.58%) |

### Bootstrap 95% Confidence Intervals (1,000 Resamples)
- **F1-Score**: `0.9452` `[0.9410, 0.9494]`
- **Recall**: `0.9043` `[0.8971, 0.9116]`
- **FPR**: `0.0092` `[0.0070, 0.0115]`
- **ROC-AUC**: `0.9887` `[0.9870, 0.9904]`

### Size-Matched Test Evaluation (1:1 per Size Bin, $N = 8,306$: 4,153 Benign / 4,153 Malicious)
- **Accuracy**: `0.9520` | **Precision**: `0.9858` | **Recall**: `0.9172` | **F1**: `0.9502` | **ROC-AUC**: `0.9833` | **FPR**: `0.0132` (vs `0.0092` on full test).
- **Large-File Observation**: Very few malicious samples exist above 1.1 MB in the test set—Bin 6 (1.1 MB–4.85 MB, 30 malicious) recall `33.33%`, Bin 7 (4.85 MB–20.9 MB, 7 malicious) recall `0.00%`, Bin 8 (>20.9 MB, 1 malicious) recall `0.00%`. This suggests a potential large-file blind spot that cannot be statistically confirmed due to low sample counts.
- **Sub-100 KB Benign Penalty**: Benign test files `< 100 KB` ($n=743$) experience **5.65% FPR** (42 false positives) vs **0.25% FPR** (13 false positives) for benign files `>= 100 KB` ($n=5,257$), a **22.86x** FPR disparity.

### `/URI` Link Indicator Dependence (`reports/uri_dependence.json`)
- **SHAP Attribution Share**: `strings_regex_/URI` accounts for **19.36%** of total global mean $|SHAP|$ (`1.4109` out of `7.2883`).
- **Malicious Recall**:
  - Malicious PDFs with `/URI == 0` ($n=1,067$): **62.23%** recall (664/1,067 at default threshold) and **71.32%** recall (761/1,067 at calibrated threshold $t=0.4083$).
  - Malicious PDFs with `/URI > 0` ($n=4,933$): **96.51%** recall (4,761/4,933 at default threshold) and **97.36%** recall (4,803/4,933 at calibrated threshold).
- **Benign FPR**:
  - Benign PDFs with `/URI == 0` ($n=4,725$): **0.38%** FPR (default) / **0.97%** FPR (calibrated).
  - Benign PDFs with `/URI > 0` ($n=1,275$): **2.90%** FPR (default) / **5.65%** FPR (calibrated).

### Operating Threshold, Review Band & Error Counts (`models/thresholds.json`)
- **Optimal Operating Threshold**: $t = 0.4083$ on calibrated probability (Validation FPR `0.820%`, Recall `97.80%`; Test FPR `1.967%`, Recall `92.73%`).
- **Manual-Review Band**: **$[0.290, 0.550]$**
  - **Validation ($N = 9,999$)**: Review Rate **1.83%** (183 docs), Auto-Decided Accuracy **99.09%**. Total errors at $t=0.4083$: **151** (62 / `41.06%` inside band; 89 / `58.94%` outside band: 37 FP, 52 FN).
  - **Test ($N = 12,000$)**: Review Rate **3.77%**, Auto-Decided Accuracy **97.24%**. Total errors at $t=0.4083$: **554** (235 / `42.42%` inside band; 319 / `57.58%` outside band: 102 FP, 217 FN).
- **Split-Conformal Prediction ($\alpha = 0.05$)**: $q_{\text{hat}} = 0.0792$, empirical test coverage **89.72%** (reflecting temporal concept drift relative to the nominal 95% guarantee).

---

## 5. Temporal & Covariate Drift Findings

- **Adversarial Covariate Drift ROC-AUC**: **0.7443** (Train vs Validation) and **0.8344** (Train vs Test), confirming measurable distribution shift across weekly cohorts.
- **Calibration Drift**: Calibrated Validation Brier Score = `0.0117` (ECE = `3.15e-08`), degrading on unseen Test Weeks 52–63 to Brier Score = `0.0344` (ECE = `0.0214`).
- **Review-Rate Drift**: Across Weeks 42–63, the manual-review rate increases at an OLS linear slope of **+0.1463% per week**, rising from a **1.83%** validation mean to a **3.77%** test mean (peaking at **5.10%** in Week 62).

---

## 6. Explainability Method

- **Method**: Exact `shap.TreeExplainer` computed over all 658 features in log-odds margin space.
- **Feature Families** (6 global families, sorted by summed mean $|SHAP|$ on 3,000 test samples):
  1. **Regex Indicators** (`51.1%` share): Keyword/regex counts such as `/URI`, `https://`, `javascript`, `/EmbeddedFile`.
  2. **Byte Histogram** (`28.4%` share): Normalized 256-bin byte frequency counts.
  3. **String Metadata** (`11.1%` share): `strings_numstrings`, `strings_avlength`, `strings_printables`, `strings_entropy`.
  4. **Byte-Entropy Histogram** (`6.2%` share): Joint 16x16 local window entropy and byte-value bins.
  5. **General Info** (`3.2%` share): File size (`general_size`), whole-file Shannon entropy (`general_entropy`), and header start bytes.
  6. **Printable Characters** (`0.0%` global summary share, though individual ASCII character frequencies frequently contribute to local explanations).

---

## 7. Safety Design of the Extractor

- **No Execution**: Files are never opened, parsed as PDF object trees, rendered, or executed. Extraction operates strictly on raw byte streams via `thrember` (`GeneralFileInfo`, `ByteHistogram`, `ByteEntropyHistogram`, `StringExtractor`) with `pe=None`.
- **Input Validation & Memory Isolation**:
  - Enforces `%PDF` magic-byte header verification.
  - Enforces a strict **20 MB** upload limit in the FastAPI service (**50 MB** in the underlying extractor).
  - Processes uploads strictly in-memory without writing uploaded files to disk.
  - Sanitizes file names via `os.path.basename` and null-byte stripping to prevent directory traversal.
- **Out-of-Distribution (OOD) Guard**: Flags documents falling outside the training 0.5th–99.5th percentiles (`358 B` to `30,602,208 B` file size; `17` to `181,974.5` extracted strings).

---

## 8. Known Limitations

1. **Static Features Only**: Cannot detect runtime-only exploits, obfuscated JavaScript payloads that execute cleanly in memory, or zero-day parser memory corruption.
2. **Heavy Link (`/URI`) Dependence**: Nearly one-fifth of global attribution (`19.36%`) depends on `/URI` counts; malicious PDFs without links drop to `62.23%` recall (default threshold), while link-heavy benign files face higher false positives.
3. **Sub-100 KB Benign Penalty**: Benign PDFs under 100 KB experience a `5.65%` FPR (`22.86x` higher than $\ge 100$ KB benigns).
4. **Stepwise Isotonic Calibration Plateau**: Raw XGBoost probabilities in `[0.2004, 0.3034]` collapse onto a flat isotonic plateau at calibrated $P = 0.4082$ (`40.8%`), routing them to the manual-review band.
5. **Not Tested on Live Malware**: Evaluated strictly on the EMBER2024 static feature benchmark.
6. **Not an Antivirus Replacement**: Intended solely as an auxiliary triage layer.

---

## 9. Ethical & Operational Notes

- **Human-in-the-Loop Accountability**: The selective review band is designed to prevent silent automated misclassifications on drifted or ambiguous documents; operators must review escalated files rather than treating `40.8%` plateau outputs as definitive malicious or benign verdicts.
- **Privacy**: The local web application performs inference in-memory and retains zero document contents on disk.
- **Dual-Use Awareness**: Feature importance disclosures (such as `/URI` reliance) are documented transparently for defensive awareness and highlight why static pre-filters must be paired with dynamic analysis.

---

Generated from: reports/best_params.json, reports/model_comparison.csv, reports/uri_dependence.json, models/thresholds.json, data/processed/preprocessing_report.json, notebooks/04_modeling.ipynb, notebooks/05_explain_uncertainty.ipynb
