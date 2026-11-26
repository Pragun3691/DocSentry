# DocSentry Model Card

**Model**: DocSentry PDF Malware Classifier (`XGBoost` + `IsotonicRegression` Calibrator)  
**Task**: Static, explainable, uncertainty-aware binary triage (`benign`, `needs_review`, `malicious`) for PDF documents  
**Dataset**: EMBER2024 Benchmark PDF Subset  

---

## 1. Intended Use and Non-Use

### Intended Use
- **Rapid Pre-Filter & Triage Assistant**: Designed for security analysts and automated ingestion pipelines to quickly score incoming PDF files using pure static byte-level features without opening, rendering, or executing the file.
- **Uncertainty-Aware Escalation**: Routes borderline, high-uncertainty documents falling within the calibrated probability interval [0.290, 0.550] to human review rather than forcing low-confidence automated verdicts.
- **Explainable Diagnostics**: Provides local SHAP feature attributions and plain-language summaries to assist human analysts during manual triage.

### Out-of-Scope / Non-Use
- **Not an Antivirus Replacement**: Must not be used as a standalone endpoint protection product or a substitute for signature-based AV and dynamic sandboxing.
- **Not Tested on Live Wild Malware**: All evaluation metrics are measured on the EMBER2024 benchmark subset; performance against novel, live zero-day exploits or adversarial evasion campaigns in the wild is unverified.
- **No Exploit / CVE Attribution**: The model classifies structural risk probability and does not identify specific CVEs, shellcode payloads, or software vulnerabilities.

---

## 2. Training & Evaluation Data

- **Source**: EMBER2024 PDF subset (`thrember` static feature extraction).
- **Deduplication**: SHA-256 deduplication across 64 weekly `.jsonl` partitions, plus removal of 1 TLSH near-duplicate overlap between **validation (week 45) and test (week 63)** (`data/processed/preprocessing_report.json`).
- **Temporal Split (42 / 10 / 12 Weeks)**:
  - **Train (Weeks 0–41)**: **42,000** documents (21,000 benign, 21,000 malicious)
  - **Validation (Weeks 42–51)**: **9,999** documents (5,000 benign, 4,999 malicious)
  - **Test (Weeks 52–63)**: **12,000** documents (6,000 benign, 6,000 malicious)
  - **Total Deduplicated Corpus**: **63,999** documents.
- **Feature Space**: **658** static numeric features (reduced from 696 raw features by dropping 38 constant/zero-variance features identified strictly on the training split).

---

## 3. Model Architecture & Selection

- **Selection Criterion**: Chosen among Logistic Regression, Random Forest, XGBoost, and HistGradientBoosting based on **Validation F1-Score** (`0.9824`, Validation Recall `0.9688`, Validation ROC-AUC `0.9977`). HistGradientBoosting achieved a slightly higher test F1 (`0.9479`, 95% bootstrap CI `[0.9439, 0.9521]`) than XGBoost (`0.9451`, 95% bootstrap CI `[0.9410, 0.9494]`), but the champion was selected on validation F1 only (`0.9824` vs `0.9810`), and the two test F1 95% confidence intervals overlap.
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

## 4. Quantitative Evaluation Metrics (Test Set, N = 12,000)

### Standard Unmatched Test Performance (t = 0.50 on Raw Scores, `reports/model_comparison.csv`)
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

### Operating Points: Raw (t = 0.50) vs. Calibrated (t = 0.4083)
The web application uses **Calibrated XGBoost at t = 0.4083** with manual-review band [0.290, 0.550]. Note that the "Standard Unmatched Test Performance" table above is at `t = 0.50` on raw scores, whereas the OOD accuracy figures in Section 5 (`95.35%` / `95.38%`) are at the calibrated threshold `t = 0.4083`.

| Split | Operating Point | Accuracy | Precision | Recall | FPR | FNR | F1 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Validation (N = 9,999)** | Raw XGBoost (t = 0.50) | 0.9826 | 0.9963 | 0.9688 | 0.0036 | 0.0312 | 0.9824 |
| **Validation (N = 9,999)** | Calibrated XGBoost (t = 0.4083) | 0.9849 | 0.9917 | 0.9780 | 0.0082 | 0.0220 | 0.9848 |
| **Test (N = 12,000)** | Raw XGBoost (t = 0.50) | 0.9475 | 0.9900 | 0.9042 | 0.0092 | 0.0958 | 0.9451 |
| **Test (N = 12,000)** | Calibrated XGBoost (t = 0.4083) | 0.9538 | 0.9792 | 0.9273 | 0.0197 | 0.0727 | 0.9526 |

### Bootstrap 95% Confidence Intervals (1,000 Resamples, Raw t = 0.50)
- **F1-Score**: `0.9452` `[0.9410, 0.9494]`
- **Recall**: `0.9043` `[0.8971, 0.9116]`
- **FPR**: `0.0092` `[0.0070, 0.0115]`
- **ROC-AUC**: `0.9887` `[0.9870, 0.9904]`

### Size-Matched Test Evaluation (1:1 per Size Bin, N = 8,306: 4,153 Benign / 4,153 Malicious)
- **Accuracy**: `0.9520` | **Precision**: `0.9858` | **Recall**: `0.9172` | **F1**: `0.9502` | **ROC-AUC**: `0.9833` | **FPR**: `0.0132` (vs `0.0092` on full test).
- **Large-File Observation**: Very few malicious samples exist above 1.1 MB in the test set—Bin 6 (1.1 MB–4.85 MB, 30 malicious) recall `33.33%`, Bin 7 (4.85 MB–20.9 MB, 7 malicious) recall `0.00%`, Bin 8 (>20.9 MB, 1 malicious) recall `0.00%`. This suggests a potential large-file blind spot that cannot be statistically confirmed due to low sample counts.
- **Sub-100 KB Benign Penalty**: Benign test files `< 100 KB` (n = 743) experience **5.65% FPR** (42 false positives) vs **0.25% FPR** (13 false positives) for benign files `>= 100 KB` (n = 5,257), a **22.86x** FPR disparity.

### `/URI` Link Indicator Dependence (`reports/uri_dependence.json`)
- **SHAP Attribution Share**: `strings_regex_/URI` accounts for **19.36%** of total global mean `|SHAP|` (`1.4109` out of `7.2883`).
- **Malicious Recall**:
  - Malicious PDFs with `/URI == 0` (n = 1,067): **62.23%** recall (664/1,067 at default threshold 0.50) and **71.32%** recall (761/1,067 at calibrated threshold `t = 0.4083`).
  - Malicious PDFs with `/URI > 0` (n = 4,933): **96.51%** recall (4,761/4,933 at default threshold 0.50) and **97.36%** recall (4,803/4,933 at calibrated threshold `t = 0.4083`).
- **Benign FPR**:
  - Benign PDFs with `/URI == 0` (n = 4,725): **0.38%** FPR (18/4,725 default) / **0.97%** FPR (46/4,725 calibrated).
  - Benign PDFs with `/URI > 0` (n = 1,275): **2.90%** FPR (37/1,275 default) / **5.65%** FPR (72/1,275 calibrated; these two figures—72/1,275 for `/URI > 0` and 42/743 for sub-100 KB—are equal by coincidence; they are different subsets).

### Review Band & Error Counts (`models/thresholds.json`, `reports/model_card_metrics.json`)
- *Definition*: An error is defined as a misclassification at the operating threshold `t = 0.4083` on calibrated probability (inside-band errors fall within [0.290, 0.550]; outside-band errors fall outside it).
- **Manual-Review Band**: **[0.290, 0.550]**
  - **Validation (N = 9,999)**: Review Rate **1.83%** (183 docs), Auto-Decided Accuracy **99.09%**. Total errors at `t = 0.4083`: **151** (62 / `41.06%` inside band: 4 FP, 58 FN; 89 / `58.94%` outside band: 37 FP, 52 FN).
  - **Test (N = 12,000)**: Review Rate **3.77%**, Auto-Decided Accuracy **97.24%**. Total errors at `t = 0.4083`: **554** (235 / `42.42%` inside band: 16 FP, 219 FN; 319 / `57.58%` outside band: 102 FP, 217 FN).
- **Split-Conformal Prediction (alpha = 0.05)**: `q_hat = 0.0792`, empirical test coverage **89.72%** (reflecting temporal concept drift relative to the nominal 95% guarantee).

---

## 5. Counterfactual and Ablation Analysis (`reports/uri_counterfactual.json`, `reports/uri_counterfactual_summary.csv`)

- **Link Removal Counterfactual (`/URI = 0` on all 12,000 test files)**:
  - All 5,792 files whose `/URI` was already 0 remained strictly unchanged.
  - Recall at `t = 0.4083` (calibrated probability `>= 0.4083`) falls from **92.73% to 63.45%** (paired bootstrap 95% CI for change: `[-30.51%, -28.13%]`) and the review rate rises from **3.77% to 16.02%**.
  - Among the 4,933 link-bearing malicious files, **1,814** lose the `malicious` verdict (calibrated probability `> 0.550`, above the review band): **1,619** move to `needs_review` and **195** move to `benign`. Note that `"recall at t = 0.4083"` (`>= 0.4083`) and `"malicious verdict"` (`> 0.550`) are distinct definitions, so the 1,814 malicious-verdict losses and the 29.28-point recall fall are different quantities.
- **Link Addition Counterfactual (`/URI = 1, 5, 25` on all 12,000 test files)**:
  - Injecting `/URI = 1`, `5`, or `25` raised benign FPR at `t = 0.4083` from **1.97%** to **12.60%**, **12.13%**, and **13.40%** respectively (and raised malicious recall to `95.98%`, `95.78%`, and `95.92%`).
- **Retrained Feature Ablations (same XGBoost hyperparameters, seed 42, evaluated at `t = 0.50`)**:
  - **Control (658 features)**: Val F1 = `0.9824` | Test F1 = `0.9451` (`[0.9410, 0.9494]`), Recall = `0.9042`, FPR = `0.0092`, ROC-AUC = `0.9887`.
  - **Without `/URI` (657 features)**: Val F1 = `0.9784` | Test F1 = `0.9476` (`[0.9436, 0.9516]`), Recall = `0.9082`, FPR = `0.0087`, ROC-AUC = `0.9870`. Because the test F1 95% intervals overlap (`0.9476` vs `0.9451`), there is **no loss** in test F1; link information is partly redundant with other features in this dataset (an untested hypothesis is that byte or character frequencies of `'/'`, `'U'`, `'R'`, `'I'` or URL schemes act as proxies).
  - **Without all 77 regex features (581 features)**: Val F1 = `0.9573` | Test F1 = `0.9388` (`[0.9343, 0.9433]`), Recall = `0.8950`, FPR = `0.0117`, ROC-AUC = `0.9842`—a small but real loss compared to the 658-feature control.
- *Counterfactual Validity Note*: Edits to the feature table are not real PDF edits, and none of this measures real-world evasion.

### Domain-Shift Check on Demo Files (`reports/domain_shift_demo.csv`)
Compared against the training benign distribution, the five small synthetic PDFs (`synthetic_a`–`synthetic_e`) fall in the low tail of file size (`0.00`th–`4.80`th percentile), string count (`4.27`th–`5.73`th percentile), and entropy (`0.23`th–`0.65`th percentile). `synthetic_f_large_5mb.pdf` is not in the low size tail: its 5.5 MB padding places it at the `87.99`th size and `98.41`th string-count percentile, while its entropy remains in the low tail (`0.26`th percentile). By contrast, the 9 anonymised user PDFs (`user_pdf_1.pdf`–`user_pdf_9.pdf`) are spread across the range of the training benign files with none in the extreme tails: size spans `9.20`th–`74.29`th percentile (5 of 9 are below the 25th percentile, from `9.20`th to `23.37`th), string count spans `15.10`th–`73.66`th percentile, and entropy spans `11.24`th–`91.53`th percentile; 7 are classified `benign` and 2 (`user_pdf_3.pdf` at `92.46`th `/URI` percentile and `user_pdf_8.pdf` at `89.46`th `/URI` percentile) are routed to `needs_review`.

> **Column note (`uri_pct_rank`):** `uri_pct_rank = 82.84` is a tie plateau meaning **zero links** (`82.84%` of training benign files have `/URI = 0`), not the 83rd percentile of link-heavy files. Any value above `82.84` indicates at least one `/URI` link (`user_pdf_7.pdf` at `88.29`, `user_pdf_8.pdf` at `89.46`, `user_pdf_3.pdf` at `92.46`, and `synthetic_d_25_uris.pdf` at `96.10`).

#### Why Synthetic & Flagged Demo Files Are Scored This Way (Top-5 SHAP Contributors)
SHAP attribution from the shipped XGBoost model shows that `synthetic_a`, `synthetic_b`, and `synthetic_c` are **not** flagged for links or keywords—having zero `/URI` annotations (`-0.9610` to `-1.2412` SHAP) and zero `https://` (`-0.2841` to `-0.3995` SHAP) actually pushes them toward `benign`. Instead, they are pushed into `needs_review` or `malicious` by their low extracted string counts (`+0.6290` to `+0.8631` SHAP) and raw byte/character distributions (e.g., byte `0x49` at `+0.3727` to `+0.4330` SHAP). `synthetic_f` is pushed strongly toward `benign` by zero links (`-1.2332`), high string count (`-0.7603`), and large file size (`-0.5638`), yielding a low raw probability (`0.2080`), but lands on the isotonic calibrator's `0.4082` plateau. Only `synthetic_d` (`/URI` `+1.6358`, `https://` `+0.4282`) and `synthetic_e` (`javascript` `+1.8834`) are driven by link counts or script keywords. Across all 15 demo files, **3** (`synthetic_a_minimal_blank.pdf`, `synthetic_f_large_5mb.pdf`, and `user_pdf_8.pdf`) sit on the calibrator's `0.4082` plateau, which is why they receive `needs_review`.

| File | Verdict (Cal / Raw) | Top-5 SHAP Contributors (`readable_name`: `shap_value`, `direction`) |
| --- | --- | --- |
| `synthetic_a_minimal_blank.pdf` | `needs_review` (`0.4082` / `0.2503`) | 1. Link annotations (/URI) count (`-1.2412`, benign); 2. Total extracted string count (`+0.6290`, malicious); 3. Frequency of byte 0x49 (`+0.4330`, malicious); 4. Secure web protocol (https://) count (`-0.3995`, benign); 5. Occurrences of the word 'resource' (`+0.3784`, malicious) |
| `synthetic_b_one_page_text.pdf` | `malicious` (`0.9808` / `0.7098`) | 1. Link annotations (/URI) count (`-1.1776`, benign); 2. Total extracted string count (`+0.8216`, malicious); 3. Frequency of byte 0x49 (`+0.4140`, malicious); 4. Secure web protocol (https://) count (`-0.3153`, benign); 5. Frequency of the character 'p' in text (`-0.2369`, benign) |
| `synthetic_c_20_page_report.pdf` | `malicious` (`0.7826` / `0.4480`) | 1. Link annotations (/URI) count (`-0.9610`, benign); 2. Total extracted string count (`+0.8631`, malicious); 3. Frequency of byte 0x49 (`+0.3727`, malicious); 4. Secure web protocol (https://) count (`-0.2841`, benign); 5. Frequency of the character '-' in text (`+0.2497`, malicious) |
| `synthetic_d_25_uris.pdf` | `malicious` (`0.9877` / `0.8654`) | 1. Link annotations (/URI) count (`+1.6358`, malicious); 2. Occurrences of the word 'system' (`-0.5151`, benign); 3. Secure web protocol (https://) count (`+0.4282`, malicious); 4. Frequency of the character 'a' in text (`-0.3853`, benign); 5. Total extracted string count (`+0.2908`, malicious) |
| `synthetic_e_embedded_js.pdf` | `malicious` (`0.9953` / `0.9412`) | 1. Occurrences of the word 'javascript' (`+1.8834`, malicious); 2. Link annotations (/URI) count (`-0.8962`, benign); 3. Total extracted string count (`+0.7767`, malicious); 4. Frequency of byte 0x49 (`+0.2925`, malicious); 5. Secure web protocol (https://) count (`-0.2506`, benign) |
| `synthetic_f_large_5mb.pdf` | `needs_review` (`0.4082` / `0.2080`) | 1. Link annotations (/URI) count (`-1.2332`, benign); 2. Total extracted string count (`-0.7603`, benign); 3. Total file size (bytes) (`-0.5638`, benign); 4. Frequency of byte 0xCF (`+0.3627`, malicious); 5. Total printable characters (`-0.3482`, benign) |
| `user_pdf_3.pdf` | `needs_review` (`0.2984` / `0.1069`) | 1. Embedded files (/EmbeddedFile) count (`+1.4482`, malicious); 2. Total printable characters (`-0.9163`, benign); 3. Link annotations (/URI) count (`+0.7332`, malicious); 4. Total extracted string count (`-0.6285`, benign); 5. Occurrences of the word 'decode' (`-0.4782`, benign) |
| `user_pdf_8.pdf` | `needs_review` (`0.4082` / `0.2561`) | 1. Link annotations (/URI) count (`+1.0432`, malicious); 2. Frequency of the character 'p' in text (`-0.6994`, benign); 3. Secure web protocol (https://) count (`+0.6541`, malicious); 4. Frequency of the character 'd' in text (`-0.5171`, benign); 5. Low-entropy bytes 0x60-0x6F (2.0-2.5 bits) (`-0.3805`, benign) |

---

## 6. Temporal & Covariate Drift Findings

- **Adversarial Covariate Drift ROC-AUC**: **0.7443** (Train vs Validation) and **0.8344** (Train vs Test), confirming measurable distribution shift across weekly cohorts.
- **Calibration Drift**: On unseen Test Weeks 52–63, calibrated Brier Score = `0.0344` (ECE = `0.0214`), compared to **in-sample** calibrated Validation Brier Score = `0.0117` (ECE = `3.15e-08`, where the isotonic calibrator was fitted).
- **Review-Rate Drift**: Across Weeks 42–63, the manual-review rate increases at an OLS linear slope of **+0.1463% per week**, rising from a **1.83%** validation mean to a **3.77%** test mean (peaking at **5.10%** in Week 62).
- **Out-of-Distribution (OOD) Warning**: Flagged files (`general_size` or `strings_numstrings` outside the training 0.5th–99.5th percentile envelope) make up **0.36%** of the test set (`43 / 12,000`), and warned accuracy (**95.35%** at `t = 0.4083`) equals unwarned accuracy (**95.38%** at `t = 0.4083`), confirming the warning serves as a distribution sanity check rather than an error predictor.

---

## 7. Explainability Method

- **Method**: Exact `shap.TreeExplainer` computed over all 658 features in log-odds margin space.
- **Feature Families** (6 global families, computed over all 658 features on the 3,000-row stratified test sample with 100-row training background; total summed mean `|SHAP| = 7.2883`, summing to `100.00%` at 2 decimals):
  1. **Regex Indicators**: `2.7882` (**38.26%**; 1-dec rounded `38.3%`) — Keyword/regex counts such as `/URI`, `https://`, `javascript`, `/EmbeddedFile`.
  2. **Printable Characters**: `1.8346` (**25.17%**; 1-dec rounded `25.2%`) — 96-bin printable ASCII character frequency distribution (`strings_printabledist_*`).
  3. **Byte Histogram**: `1.5465` (**21.22%**; 1-dec rounded `21.2%`) — Normalized 256-bin byte frequency counts.
  4. **String Metadata**: `0.6063` (**8.32%**; 1-dec rounded `8.3%`) — `strings_numstrings`, `strings_avlength`, `strings_printables`, `strings_entropy`.
  5. **Byte-Entropy Histogram**: `0.3392` (**4.65%**; 1-dec rounded `4.7%`) — Joint 16x16 local window entropy and byte-value bins.
  6. **General Info**: `0.1735` (**2.38%**; 1-dec rounded `2.4%`) — File size (`general_size`), whole-file Shannon entropy (`general_entropy`), and header start bytes.

---

## 8. Safety Design of the Extractor

- **No Execution**: Files are never opened, parsed as PDF object trees, rendered, or executed. Extraction operates strictly on raw byte streams via `thrember` (`GeneralFileInfo`, `ByteHistogram`, `ByteEntropyHistogram`, `StringExtractor`) with `pe=None`.
- **Input Validation & Memory Isolation**:
  - Enforces `%PDF` magic-byte header verification.
  - Enforces a strict **20 MiB** upload limit in the FastAPI service (**50 MB** in the underlying extractor).
  - Processes uploads strictly in-memory without writing uploaded files to disk.
  - Sanitizes file names via `os.path.basename` and null-byte stripping to prevent directory traversal.
- **Out-of-Distribution (OOD) Guard**: Flags documents falling outside the training 0.5th–99.5th percentiles (`358 B` to `30.6 MB` [`30,602,208 B`] file size; `17` to `181,974.5` extracted strings).

---

## 9. Known Limitations

1. **Static Features Only**: Cannot detect runtime-only exploits, obfuscated JavaScript payloads that execute cleanly in memory, or zero-day parser memory corruption.
2. **Heavy Link (`/URI`) Dependence**: Nearly one-fifth of global attribution (`19.36%`) depends on `/URI` counts; malicious PDFs without links drop to `62.23%` recall (default threshold 0.50) / `71.32%` recall (calibrated threshold `t = 0.4083`), while link-heavy benign files face higher false positives.
3. **Sub-100 KB Benign Penalty**: Benign PDFs under 100 KB experience a `5.65%` FPR (`22.86x` higher than `>= 100 KB` benigns).
4. **Stepwise Isotonic Calibration Plateau**: Raw XGBoost probabilities in `[0.2004, 0.3034]` collapse onto a flat isotonic plateau at calibrated `P = 0.4082` (`40.8%`), routing them to the manual-review band.
5. **Not Run on Real Malicious PDFs**: Evaluated only on EMBER2024 feature data; the extractor and app have never been run on real malicious PDFs.
6. **Not an Antivirus Replacement**: Intended solely as an auxiliary triage layer.

---

## 10. Ethical & Operational Notes

- **Human-in-the-Loop Accountability**: The selective review band is designed to prevent silent automated misclassifications on drifted or ambiguous documents; operators must review escalated files rather than treating `40.8%` plateau outputs as definitive malicious or benign verdicts.
- **Privacy**: The local web application performs inference in-memory and retains zero document contents on disk.
- **Dual-Use Awareness**: Feature importance disclosures (such as `/URI` reliance) are documented transparently for defensive awareness and highlight why static pre-filters must be paired with dynamic analysis.

---

Generated from: reports/best_params.json, reports/model_comparison.csv, reports/uri_dependence.json, reports/model_card_metrics.json, reports/uri_counterfactual.json, reports/uri_counterfactual_summary.csv, reports/domain_shift_demo.csv, models/thresholds.json, data/processed/preprocessing_report.json, notebooks/04_modeling.ipynb, notebooks/05_explain_uncertainty.ipynb, notebooks/08_uri_counterfactual.ipynb
