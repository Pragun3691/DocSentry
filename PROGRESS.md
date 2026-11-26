# DocSentry Project Progress Log

**DocSentry** is an explainable, uncertainty-aware PDF malware detector built upon static features extracted from the EMBER2024 benchmark subset ([FutureComputing4AI/EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)).

---

## Notebook 01: Data Understanding (`notebooks/01_data_understanding.ipynb`)
- **Phase**: Read-only exploration and data ingestion sanity audit.
- **Completed**: 2026-11-24
- **Files Created**:
  - [`notebooks/01_data_understanding.ipynb`](file:///<PROJECT_ROOT>/notebooks/01_data_understanding.ipynb)
  - [`reports/figures/01_label_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/01_label_distribution.png)
  - [`reports/figures/02_missing_values.png`](file:///<PROJECT_ROOT>/reports/figures/02_missing_values.png)
  - [`reports/figures/03_feature_families.png`](file:///<PROJECT_ROOT>/reports/figures/03_feature_families.png)
  - [`reports/figures/04_numeric_features_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/04_numeric_features_distribution.png)
- **Key Numbers & Findings**:
  - **Raw Corpus**: 64 weekly `.jsonl` files (52 train + 12 test), totaling 128,000 raw lines (151.4 MB compressed).
  - **Raw Balance**: Train contains 104,000 records (52,000 benign, 52,000 malicious; 50.0% / 50.0%). Test contains 24,000 records (12,000 benign, 12,000 malicious; 50.0% / 50.0%).
  - **Missing Values**: 0 missing values across all numeric static feature families.
  - **Feature Families**: Identified 4 nested static families (`general` with 7 features, `histogram` with 256, `byteentropy` with 256, `strings` with 177), yielding 696 candidate numeric inputs.
  - **Metadata Isolation**: Documented non-input columns (`sha256`, `md5`, `sha1`, `tlsh`, submission dates, AV scan dates, `detection_ratio`, `family`, `behavior`).

---

## Notebook 02: Exploratory Data Analysis (`notebooks/02_eda.ipynb`)
- **Phase**: In-depth univariate, bivariate, and multivariate distribution analysis.
- **Completed**: 2026-11-24
- **Files Created**:
  - [`notebooks/02_eda.ipynb`](file:///<PROJECT_ROOT>/notebooks/02_eda.ipynb)
  - [`data/processed/dedup_train.parquet`](file:///<PROJECT_ROOT>/data/processed/dedup_train.parquet) (52,000 samples)
  - [`data/processed/dedup_test.parquet`](file:///<PROJECT_ROOT>/data/processed/dedup_test.parquet) (12,000 samples)
  - 13 figures in `reports/figures/`:
    - [`05_class_balance_dedup.png`](file:///<PROJECT_ROOT>/reports/figures/05_class_balance_dedup.png)
    - [`06_file_size_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/06_file_size_distribution.png)
    - [`07_file_entropy_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/07_file_entropy_distribution.png)
    - [`08_string_stats_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/08_string_stats_distribution.png)
    - [`09_mean_byte_histogram.png`](file:///<PROJECT_ROOT>/reports/figures/09_mean_byte_histogram.png)
    - [`10_zero_inflation_histogram.png`](file:///<PROJECT_ROOT>/reports/figures/10_zero_inflation_histogram.png)
    - [`11_feature_skewness_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/11_feature_skewness_distribution.png)
    - [`12_top25_effect_size_cohens_d.png`](file:///<PROJECT_ROOT>/reports/figures/12_top25_effect_size_cohens_d.png)
    - [`13_top8_separating_violins.png`](file:///<PROJECT_ROOT>/reports/figures/13_top8_separating_violins.png)
    - [`14_string_indicators_heatmap.png`](file:///<PROJECT_ROOT>/reports/figures/14_string_indicators_heatmap.png)
    - [`15_non_histogram_correlation_heatmap.png`](file:///<PROJECT_ROOT>/reports/figures/15_non_histogram_correlation_heatmap.png)
    - [`16_pca_2d_projection.png`](file:///<PROJECT_ROOT>/reports/figures/16_pca_2d_projection.png)
    - [`17_train_test_distribution_shift.png`](file:///<PROJECT_ROOT>/reports/figures/17_train_test_distribution_shift.png)
- **Key Numbers & Findings**:
  - **Deduplication Audit**: Deduplication on `sha256` reduced training from 104,000 to exactly 52,000 unique records (26,000 benign, 26,000 malicious) and test from 24,000 to exactly 12,000 unique records (6,000 benign, 6,000 malicious).
  - **Feature Reconciliation**: Reconciled the 689 vs. 696 difference: 689 represents the subset of byte histograms (256), byte-entropy histograms (256), and strings (177), whereas 696 includes all 7 `GeneralFileInfo` features (`general_size`, `general_entropy`, `general_is_pe`, and 4 header start bytes).
  - **StringExtractor Reconciliation**: Reconciled the 76 vs. 77 regex count: `StringExtractor` has 4 scalar statistics + 96 printable distribution bins + 77 compiled regex patterns = 177 features. 3 are explicit PDF keywords (`/URI`, `/FlateDecode`, `/EmbeddedFile`).
  - **Empirical Distributions**:
    - Median file size: Benign 463,940.5 bytes vs. Malicious 93,821.5 bytes (benign ~4.9x larger).
    - Mean Shannon entropy: Benign 7.6988 vs. Malicious 7.7653 (malicious higher, reflecting packed/encrypted payloads).
    - Mean string count: Benign 15,254.2 vs. Malicious 1,102.4 (benign ~13.8x richer).
  - **Bug Discovery**: Uncovered a copy-paste duplication in `thrember/features.py` line 202 where `email_addr` is assigned the exact regex pattern of `mac_addr`.
  - **PCA & Separation**: 2D PCA on 5,000 stratified samples showed non-linear class separation with substantial boundary overlap.

---

## Notebook 03: Data Preprocessing & Leakage Prevention (`notebooks/03_preprocessing.ipynb`)
- **Phase**: Temporal train/val/test splitting, fuzzy hash deduplication, adversarial drift quantification, feature selection, dual normalization pipeline, and dataset serialization.
- **Completed**: 2026-11-24
- **Files Created**:
  - [`notebooks/03_preprocessing.ipynb`](file:///<PROJECT_ROOT>/notebooks/03_preprocessing.ipynb)
  - [`reports/figures/18_scaling_before_after.png`](file:///<PROJECT_ROOT>/reports/figures/18_scaling_before_after.png)
  - [`reports/figures/19_feature_reduction_waterfall.png`](file:///<PROJECT_ROOT>/reports/figures/19_feature_reduction_waterfall.png)
  - [`data/processed/X_train_tree.parquet`](file:///<PROJECT_ROOT>/data/processed/X_train_tree.parquet) (42,000 × 658, 105.74 MB)
  - [`data/processed/X_val_tree.parquet`](file:///<PROJECT_ROOT>/data/processed/X_val_tree.parquet) (9,999 × 658, 25.17 MB)
  - [`data/processed/X_test_tree.parquet`](file:///<PROJECT_ROOT>/data/processed/X_test_tree.parquet) (12,000 × 658, 30.22 MB)
  - [`data/processed/X_train_linear.parquet`](file:///<PROJECT_ROOT>/data/processed/X_train_linear.parquet) (42,000 × 658, 105.74 MB)
  - [`data/processed/X_val_linear.parquet`](file:///<PROJECT_ROOT>/data/processed/X_val_linear.parquet) (9,999 × 658, 25.17 MB)
  - [`data/processed/X_test_linear.parquet`](file:///<PROJECT_ROOT>/data/processed/X_test_linear.parquet) (12,000 × 658, 30.22 MB)
  - [`data/processed/y_train.parquet`](file:///<PROJECT_ROOT>/data/processed/y_train.parquet) (42,000 rows)
  - [`data/processed/y_val.parquet`](file:///<PROJECT_ROOT>/data/processed/y_val.parquet) (9,999 rows)
  - [`data/processed/y_test.parquet`](file:///<PROJECT_ROOT>/data/processed/y_test.parquet) (12,000 rows)
  - [`data/processed/feature_names.json`](file:///<PROJECT_ROOT>/data/processed/feature_names.json) (658 feature names in exact column order)
  - [`data/processed/scaler.joblib`](file:///<PROJECT_ROOT>/data/processed/scaler.joblib) (StandardScaler fitted strictly on X_train_linear)
  - [`data/processed/preprocessing_report.json`](file:///<PROJECT_ROOT>/data/processed/preprocessing_report.json)
- **Key Numbers & Findings**:
  - **Part A (Verification)**:
    - Confirmed 77 compiled regex patterns in `thrember`'s `StringExtractor` (3 PDF-specific keywords: `/URI`, `/FlateDecode`, `/EmbeddedFile`).
    - Empirical distributions (42-week train split): Benign median file size = 416,198.5 bytes vs. Malicious = 92,591.5 bytes; Benign mean entropy = 7.6652 vs. Malicious = 7.7608; Benign mean numstrings = 15,311.01 vs. Malicious = 1,085.60.
    - Top discriminators by Cohen's $d$: `strings_printabledist_80` ($d = +1.519$), `strings_printabledist_68` ($d = +1.350$), `strings_printabledist_79` ($d = +1.176$), `strings_printabledist_78` ($d = +1.146$), and `byte_hist_121` ($d = +0.946$).
    - Constant vs. Low-Variance Audit: 38 features are truly constant (`nunique == 1`, $\text{var} = 0$). 67 features have $\text{var} < 10^{-8}$; 28 of those 29 low-variance features are byte or byte-entropy histogram bins with non-zero values in $\ge 1\%$ of files. Dropping 66 features was demonstrated to be unjustified; only the 38 truly constant features were dropped.
  - **Part B (Cleaning & Selection)**:
    - Excluded 28 non-feature columns (hashes, dates, AV detection score, threat family labels, sandbox tags, empty PE structs).
    - Verified faulty `strings_regex_email_addr`: identical to `mac_addr` pattern, matches MAC addresses instead of email strings, and invariant 0 in training data.
    - Preserved 658 model inputs ($696 - 38 = 658$ features: 6 General, 256 ByteHistogram, 256 ByteEntropyHistogram, 140 StringExtractor).
  - **Part C (Temporal Splitting & Drift)**:
    - **Train**: Weeks 0–41 (42,000 samples: 21,000 benign, 21,000 malicious; 50.0% / 50.0%).
    - **Validation**: Weeks 42–51 (originally 10,000 samples). Cross-split TLSH audit identified exactly 1 malicious sample in Week 45 sharing an exact TLSH match (`T1EA94E0C840AD6B9FF4496C353163...`) with a test sample in Week 63. Pruned from validation to prevent evaluation leakage, leaving 9,999 validation samples (5,000 benign, 4,999 malicious).
    - **Test**: Weeks 52–63 (12,000 samples: 6,000 benign, 6,000 malicious; 50.0% / 50.0%).
    - **Cryptographic Overlap**: 0 SHA-256 matches across all splits.
    - **Adversarial Concept Drift**: Logistic regression `is_later_split` classifier yielded:
      - Train vs. Validation ROC-AUC: **0.7443**
      - Train vs. Test ROC-AUC: **0.8344**
      - Confirms significant, progressive temporal distribution shift across collection epochs.
  - **Part D (Scaling & Dual Pipeline)**:
    - `_tree`: Raw unscaled features for gradient boosting and tree ensembles.
    - `_linear`: $\log(1+x)$ transformation on 44 count/size features followed by `StandardScaler` fitted strictly on `X_train`. Validation and test transformed without leakage.
  - **Part E (Serialization & Visualizations)**:
    - Persisted dual Parquet datasets, ordered feature names, fitted scaler, and metadata report.
    - Visualized before/after scaling distributions in Figure 18 and feature reduction waterfall in Figure 19.

---

## Notebook 04: Modeling & Temporal Evaluation (`notebooks/04_modeling.ipynb`)
- **Phase**: Baseline benchmarking, 15-candidate random search tuning (train on Train, select strictly on Validation), single-pass test evaluation, size-shortcut ablation, feature importance analysis, and 4 in-depth diagnostic audits.
- **Completed**: 2026-11-24
- **Files Created / Updated**:
  - [`notebooks/04_modeling.ipynb`](file:///<PROJECT_ROOT>/notebooks/04_modeling.ipynb)
  - [`models/logistic_regression.joblib`](file:///<PROJECT_ROOT>/models/logistic_regression.joblib)
  - [`models/random_forest.joblib`](file:///<PROJECT_ROOT>/models/random_forest.joblib)
  - [`models/xgboost.joblib`](file:///<PROJECT_ROOT>/models/xgboost.joblib)
  - [`models/histgradientboosting.joblib`](file:///<PROJECT_ROOT>/models/histgradientboosting.joblib)
  - [`models/best_model.joblib`](file:///<PROJECT_ROOT>/models/best_model.joblib)
  - [`reports/model_comparison.csv`](file:///<PROJECT_ROOT>/reports/model_comparison.csv)
  - [`reports/best_params.json`](file:///<PROJECT_ROOT>/reports/best_params.json)
  - [`reports/figures/20_model_validation_comparison.png`](file:///<PROJECT_ROOT>/reports/figures/20_model_validation_comparison.png)
  - [`reports/figures/21_test_confusion_matrices.png`](file:///<PROJECT_ROOT>/reports/figures/21_test_confusion_matrices.png)
  - [`reports/figures/22_test_roc_curves.png`](file:///<PROJECT_ROOT>/reports/figures/22_test_roc_curves.png)
  - [`reports/figures/23_test_pr_curves.png`](file:///<PROJECT_ROOT>/reports/figures/23_test_pr_curves.png)
  - [`reports/figures/24_feature_importance.png`](file:///<PROJECT_ROOT>/reports/figures/24_feature_importance.png)
  - [`reports/figures/25_malicious_size_clusters.png`](file:///<PROJECT_ROOT>/reports/figures/25_malicious_size_clusters.png)
  - [`reports/figures/26_feature_importance_ascii_labeled.png`](file:///<PROJECT_ROOT>/reports/figures/26_feature_importance_ascii_labeled.png)
- **Key Numbers & Findings**:
  - **1. Integrity & Baselines**:
    - Confirmed exact feature alignment against [`feature_names.json`](file:///<PROJECT_ROOT>/data/processed/feature_names.json) (658 features) with 0 `NaN` and 0 `inf`.
    - `DummyClassifier(strategy='most_frequent')`: Accuracy = 50.01%, F1 = 0.0000, ROC-AUC = 0.5000, Recall = 0.0000.
    - Default `LogisticRegression`: Accuracy = 96.66%, Precision = 98.34%, Recall = 94.92%, F1 = 0.9660, ROC-AUC = 0.9876.
  - **2. Hyperparameter Tuning on Train (42k) / Selection on Validation (9,999)**:
    - **Logistic Regression** ($C=0.0118$, $\ell_2$, L-BFGS): Val Acc = 96.94%, Val Prec = 98.61%, Val Recall = 95.22%, **Val F1 = 0.9689**, Val ROC-AUC = 0.9893, FPR = 1.34%, Train Time = 2.49s.
    - **Random Forest** (`n_estimators=50`, `max_depth=12`, `min_samples_split=5`, `max_features=0.2`): Val Acc = 97.54%, Val Prec = 99.62%, Val Recall = 95.44%, **Val F1 = 0.9749**, Val ROC-AUC = 0.9967, FPR = 0.36%, Train Time = 34.42s.
    - **XGBoost** (`n_estimators=150`, `max_depth=5`, `learning_rate=0.05`, `subsample=0.9`, `colsample_bytree=0.7`, `tree_method='hist'`): Val Acc = 98.26%, Val Prec = 99.63%, Val Recall = 96.88%, **Val F1 = 0.9824**, Val ROC-AUC = 0.9977, FPR = 0.36%, Train Time = 41.91s.
    - **HistGradientBoosting** (`max_iter=100`, `max_depth=None`, `learning_rate=0.15`, `min_samples_leaf=20`, `l2_reg=5.0`): Val Acc = 98.13%, Val Prec = 99.71%, Val Recall = 96.54%, **Val F1 = 0.9810**, Val ROC-AUC = 0.9978, FPR = 0.28%, Train Time = 22.68s.
  - **3. Final Model Selection**:
    - **Chosen Model**: **XGBoost** achieves the highest Validation F1 score (**0.9824**) as well as highest validation malicious recall (**96.88%**).
  - **4. Single-Pass Final Test Evaluation (12,000 samples)**:
    - **Logistic Regression**: Test Acc = 94.45%, Test Prec = 97.81%, Test Recall = 90.93%, **Test F1 = 0.9425**, Test ROC-AUC = 0.9765, Test PR-AUC = 0.9803, Test FPR = 2.03%, Test FNR = 9.07%.
    - **Random Forest**: Test Acc = 93.53%, Test Prec = 99.17%, Test Recall = 87.78%, **Test F1 = 0.9313**, Test ROC-AUC = 0.9879, Test PR-AUC = 0.9903, Test FPR = 0.73%, Test FNR = 12.22%.
    - **XGBoost (Best Model)**: Test Acc = **94.75%**, Test Prec = **98.996%**, Test Recall = **90.42%**, **Test F1 = 0.9451**, Test ROC-AUC = **0.9887**, Test PR-AUC = **0.9911**, Test FPR = **0.92%**, Test FNR = **9.58%**.
    - **HistGradientBoosting**: Test Acc = 95.02%, Test Prec = 99.23%, Test Recall = 90.73%, **Test F1 = 0.9479**, Test ROC-AUC = 0.9889, Test PR-AUC = 0.9914, Test FPR = 0.70%, Test FNR = 9.27%.
    - **Validation-to-Test Drift Gap (XGBoost)**: Accuracy dropped by 3.51%, F1 by 3.72%, Recall by 6.46%, and ROC-AUC by 0.89%. This validates the temporal drift uncovered during preprocessing (ROC-AUC 0.8344 on split discrimination).
  - **5. Size-Shortcut Ablation Experiment**:
    - Removed `general_size`, `strings_numstrings`, `strings_printables`, and `strings_avlength` (658 -> 654 features).
    - Validation F1: 0.9824 (Full) vs. 0.9769 (Ablated) ($\Delta = -0.0055$ or $-0.56\%$).
    - Test F1: 0.9451 (Full) vs. 0.9330 (Ablated) ($\Delta = -0.0122$ or $-1.29\%$).
    - Test ROC-AUC: 0.9887 (Full) vs. 0.9871 (Ablated) ($\Delta = -0.0016$).
    - **Takeaway**: Removing four columns shows the model does not uniquely depend on them, but size information remains in correlated features (e.g. byte histogram totals and printable distributions), and benign files under 100 KB have a 22.9x higher FPR.
  - **6. Feature Importance Highlights**:
    - **Random Forest (Gini)**: `strings_regex_/URI` (0.1977), `strings_regex_https://` (0.0944), `strings_printabledist_80` (`'p'`, 0.0849), `strings_printables` (0.0439), `strings_regex_decode` (0.0396).
    - **XGBoost (Gain)**: `byte_entropy_04_00` (0.1217), `strings_regex_/URI` (0.1211), `byte_entropy_04_06` (0.0809), `byte_entropy_04_03` (0.0778), `strings_regex_https://` (0.0728).
  - **7. Diagnostic Audits**:
    - **Tiny Benign Files (< 1,000 bytes)**: Exactly 899 exist across the corpus, **all located exclusively in Train** (0 in Val, 0 in Test). 895 files (99.6%) share an exact size of 358 bytes (blank placeholder PDFs).
    - **Malicious Size Clusters**: 91.51% of malicious files fall in the 25 KB to 500 KB interval. The largest single mode is 100-200 KB with 5,452 files (26.0%), while 25-50 KB contains 2,810 files (13.4%).
    - **Subpopulation FPR Audit**: In the Test set, benign files $<100$ KB suffer an FPR of **5.65%** (42 / 743), compared to only **0.25%** (13 / 5,257) for benign files $\ge 100$ KB (**22.86× higher FPR**), confirming that small benign files align with malicious size modes and face disproportionate false alarm risk.
    - **ASCII / Byte-Entropy Semantics**: Decoded `strings_printabledist_i` to ASCII characters (`'p'`, `'d'`, `'<'`, `'/'`) without speculative narrative. Decoded `byte_entropy_AA_BB` from `thrember` source where index `AA` (0-15) represents the coarse entropy bin $[0.5 \times \text{AA}, 0.5 \times (\text{AA}+1))$ bits (e.g. bin 4 is 2.0-2.5 bits) and index `BB` (0-15) represents coarse byte values `0x{BB*16:02X}-0x{BB*16+15:02X}` ($16 \times \text{BB}$ to $16 \times \text{BB} + 15$).

---

## Notebook 05: Explainability, Uncertainty & Operational Reliability (`notebooks/05_explain_uncertainty.ipynb`)
- **Phase**: Statistical comparison, size-matched evaluation, validation-only probability calibration, dual-threshold review band, longitudinal uncertainty drift tracking, conformal prediction, global/local SHAP analysis, and production inference engine.
- **Completed**: 2026-11-24
- **Files Created / Updated**:
  - [`notebooks/05_explain_uncertainty.ipynb`](file:///<PROJECT_ROOT>/notebooks/05_explain_uncertainty.ipynb)
  - [`models/calibrator.joblib`](file:///<PROJECT_ROOT>/models/calibrator.joblib)
  - [`models/thresholds.json`](file:///<PROJECT_ROOT>/models/thresholds.json)
  - [`src/__init__.py`](file:///<PROJECT_ROOT>/src/__init__.py)
  - [`src/docsentry_infer.py`](file:///<PROJECT_ROOT>/src/docsentry_infer.py)
  - [`tests/test_infer.py`](file:///<PROJECT_ROOT>/tests/test_infer.py)
  - 14 figures in `reports/figures/`:
    - [`27_bootstrap_test_ci_comparison.png`](file:///<PROJECT_ROOT>/reports/figures/27_bootstrap_test_ci_comparison.png)
    - [`28_size_matched_evaluation.png`](file:///<PROJECT_ROOT>/reports/figures/28_size_matched_evaluation.png)
    - [`29_calibration_reliability_diagrams.png`](file:///<PROJECT_ROOT>/reports/figures/29_calibration_reliability_diagrams.png)
    - [`30_threshold_recall_fpr_tradeoff.png`](file:///<PROJECT_ROOT>/reports/figures/30_threshold_recall_fpr_tradeoff.png)
    - [`31_accuracy_vs_coverage_curve.png`](file:///<PROJECT_ROOT>/reports/figures/31_accuracy_vs_coverage_curve.png)
    - [`32_weekly_review_rate_drift.png`](file:///<PROJECT_ROOT>/reports/figures/32_weekly_review_rate_drift.png)
    - [`33_shap_global_importance_bar.png`](file:///<PROJECT_ROOT>/reports/figures/33_shap_global_importance_bar.png)
    - [`34_shap_summary_beeswarm.png`](file:///<PROJECT_ROOT>/reports/figures/34_shap_summary_beeswarm.png)
    - [`35_shap_family_importance_bar.png`](file:///<PROJECT_ROOT>/reports/figures/35_shap_family_importance_bar.png)
    - [`36_1_true_positive.png`](file:///<PROJECT_ROOT>/reports/figures/36_1_true_positive.png)
    - [`36_2_true_negative.png`](file:///<PROJECT_ROOT>/reports/figures/36_2_true_negative.png)
    - [`36_3_false_positive.png`](file:///<PROJECT_ROOT>/reports/figures/36_3_false_positive.png)
    - [`36_4_false_negative.png`](file:///<PROJECT_ROOT>/reports/figures/36_4_false_negative.png)
    - [`36_5_review_band.png`](file:///<PROJECT_ROOT>/reports/figures/36_5_review_band.png)
- **Key Numbers & Findings**:
  - **1. Statistical Comparison (1,000 Bootstrap Resamples on Test Set)**:
    - **HistGradientBoosting**: F1 = 0.9480 [0.9439, 0.9521], Recall = 0.9075 [0.9005, 0.9148], FPR = 0.0070 [0.0049, 0.0091], ROC-AUC = 0.9890 [0.9873, 0.9906].
    - **XGBoost**: F1 = 0.9452 [0.9410, 0.9494], Recall = 0.9043 [0.8971, 0.9116], FPR = 0.0092 [0.0070, 0.0115], ROC-AUC = 0.9887 [0.9870, 0.9904].
    - **Random Forest**: F1 = 0.9313 [0.9267, 0.9359], Recall = 0.8779 [0.8704, 0.8861], FPR = 0.0074 [0.0054, 0.0094], ROC-AUC = 0.9879 [0.9861, 0.9895].
    - **Logistic Regression**: F1 = 0.9425 [0.9379, 0.9467], Recall = 0.9094 [0.9022, 0.9164], FPR = 0.0204 [0.0169, 0.0239], ROC-AUC = 0.9766 [0.9738, 0.9791].
    - **Paired Significance (XGB - HGB)**: $\Delta$ F1 = -0.0029 (95% CI [-0.0051, -0.0006], **Significant**); $\Delta$ FPR = +0.0022 (95% CI [+0.0005, +0.0042], **Significant**); $\Delta$ Recall = -0.0032 (95% CI [-0.0071, +0.0005], **Not Significant**); $\Delta$ ROC-AUC = -0.0002 (95% CI [-0.0010, +0.0006], **Not Significant**).
  - **2. Size-Matched Evaluation ($N=8,306$, 4,153 Benign & 4,153 Malicious)**:
    - Full Test Set vs. Size-Matched: Accuracy 94.75% vs. 95.20%, Precision 98.996% vs. 98.58%, Recall 90.42% vs. 91.72%, **F1 Score 0.9451 vs. 0.9502**, ROC-AUC 0.9887 vs. 0.9833, FPR 0.92% vs. 1.32%.
    - Large-File Subpopulation Analysis: The matched test subset contains only 30, 7, and 1 malicious samples in the three largest bins (Bins 6, 7, 8), where recall drops sharply to 33.3%, 0.0%, and 0.0%. Furthermore, matched FPR (1.32%) is higher than full-test FPR (0.92%). This suggests a possible large-file blind spot, although it cannot be definitively confirmed with so few large malicious evaluation samples.
  - **3. Calibration & Reliability Analysis**:
    - **Test Calibration Metrics (Out-of-Sample)**:
      - Raw XGBoost: Test Brier = 0.044053, Test ECE = 0.053789.
      - Calibrated (Isotonic): Test Brier = **0.034355** (-22.0%), Test ECE = **0.021419** (-60.2%).
    - **Validation Calibration Metrics (In-Sample, Calibrator Fitted Here)**:
      - Raw XGBoost: Val Brier = 0.015330, Val ECE = 0.018677.
      - Calibrated (Isotonic): Val Brier = **0.011721** (-23.5%), Val ECE = **0.000000**.
    - **Operational Threshold**: $t = 0.4083$ selected on validation for $\approx 1\%$ FPR target (Val FPR = 0.820%, Val Recall = 97.80%; Test FPR = 1.967%, Test Recall = 92.73%).
    - Fixed Test FPR Operating Points: At 0.1% FPR ($t=0.9880$), Recall = **74.10%**; at 1.0% FPR ($t=0.7830$), Recall = **90.47%**; at 5.0% FPR ($t=0.2866$), Recall = **96.38%**.
  - **4. Manual-Review Band & Uncertainty Under Concept Drift**:
    - Validation-optimized band ($[low, high] = [0.290, 0.550]$): Achieves **99.09%** auto-decision accuracy on validation with a **1.83%** review rate (183 docs). On Test: **3.77%** review rate (452 docs) with **97.24%** auto-decision accuracy.
    - **Explicit Error Breakdown (Misclassification at $t = 0.4083$)**:
      - **Validation**: 151 total errors. 62 inside review band (41.06%), 89 outside band (58.94%). $62 + 89 = 151$.
      - **Test**: 554 total errors. 235 inside review band (42.42%), 319 outside band (57.58%). $235 + 319 = 554$.
      - Test Errors Outside Band: 47 False Positives, 272 False Negatives ($47 + 272 = 319$).
    - **Weekly Review Rate Drift (Figure 32)**:
      - Week 51 visualized as validation (blue); weeks 52–63 visualized as test (red).
      - OLS linear slope across weeks 42–63 is **+0.1463% / week** (+0.15% / week).
      - Peak review rate in test split is **5.10%** (Week 62).
    - Split-Conformal Prediction ($\alpha=0.05$): $q_{\text{hat}} = 0.0792$, Test Coverage = **89.72%** (Singleton Benign = 47.1%, Singleton Malicious = 44.2%, Empty Set = 8.7%).
  - **5. Dependence on `/URI` Keyword**:
    - Malicious Recall: `/URI == 0` is **62.23%** (664 / 1,067) vs. `/URI > 0` is **96.51%** (4,761 / 4,933) ($\Delta = +34.28\%$).
    - Benign FPR: `/URI == 0` is **0.38%** (18 / 4,725) vs. `/URI > 0` is **2.90%** (37 / 1,275) (7.6x higher FPR).
    - `/URI` Feature Attribution: Mean |SHAP| = 1.4109 out of 7.2883 total across all 658 features (**19.36%** of total model attribution).
  - **6. SHAP Global, Family & Local Attribution**:
    - **Top 50 Feature Attribution Stability**: Spearman rank correlation between Validation and Test SHAP feature importances is **$\rho = 0.9548$** ($p = 6.25 \times 10^{-27}$).
    - **Family-Level Attribution Shares**:
      - `regex indicators`: **38.29%** (Summed |SHAP| = 2.7946)
      - `printable-character distribution`: **24.95%** (1.8209)
      - `byte histogram`: **21.54%** (1.5723)
      - `string scalars`: **8.23%** (0.6004)
      - `byte-entropy histogram`: **4.63%** (0.3380)
      - `general/size`: **2.37%** (0.1731)
    - **Distinct Local Waterfall Case Studies (Saved as Separate Plots)**:
      - True Positive (`36_1_true_positive.png`): Index 0, Calibrated $P = 1.0000$. Driven by `/URI` (+2.06) and `https://` (+0.54).
      - True Negative (`36_2_true_negative.png`): Index 3, Calibrated $P = 0.0073$. Driven by absence of `/URI` (-1.16) and large `numstrings` (-0.46).
      - False Positive (`36_3_false_positive.png`): Index 145, Calibrated $P = 0.9953$. Benign doc containing embedded `/URI` (+1.83) and high byte-entropy bin 4 (+0.95).
      - Confident False Negative (`36_4_false_negative.png`): Index 74, Calibrated $P = 0.0258 < 0.29$. Malicious doc without `/URI` (-1.16), mimicking benign string profile.
      - Review-Band Document (`36_5_review_band.png`): Index 31, Calibrated $P = 0.4082 \in [0.29, 0.55]$. Borderline sample with conflicting indicators safely escalated to human analyst.

---

## Production Pipeline & Real-PDF Demonstration (`src/`, `tests/`, `notebooks/06_real_pdf_demo.ipynb`)
- **Phase**: Reusable static feature extractor, pipeline-fidelity unit testing, CLI batch scanning, synthetic adversarial PDF generation, and real-world evaluation demo.
- **Completed**: 2026-11-24
- **Files Created / Updated**:
  - [`src/docsentry_extract.py`](file:///<PROJECT_ROOT>/src/docsentry_extract.py)
  - [`tests/test_extract.py`](file:///<PROJECT_ROOT>/tests/test_extract.py)
  - [`scripts/generate_synthetic_pdfs.py`](file:///<PROJECT_ROOT>/scripts/generate_synthetic_pdfs.py)
  - [`scripts/scan_pdfs.py`](file:///<PROJECT_ROOT>/scripts/scan_pdfs.py)
  - [`reports/demo_scan_results.csv`](file:///<PROJECT_ROOT>/reports/demo_scan_results.csv)
  - [`notebooks/06_real_pdf_demo.ipynb`](file:///<PROJECT_ROOT>/notebooks/06_real_pdf_demo.ipynb)
  - [`reports/figures/37_demo_synthetic_shap_contributions.png`](file:///<PROJECT_ROOT>/reports/figures/37_demo_synthetic_shap_contributions.png)
  - Synthetic test PDFs in [`data/demo_pdfs/synthetic/`](file:///<PROJECT_ROOT>/data/demo_pdfs/synthetic/):
    - `synthetic_a_minimal_blank.pdf` (335 bytes)
    - `synthetic_b_one_page_text.pdf` (832 bytes)
    - `synthetic_c_20_page_report.pdf` (3,684 bytes)
    - `synthetic_d_25_uris.pdf` (7,147 bytes)
    - `synthetic_e_embedded_js.pdf` (839 bytes)
    - `synthetic_f_large_5mb.pdf` (5,500,811 bytes, 5.25 MB)
  - User PDF testing directory: [`data/demo_pdfs/user/`](file:///<PROJECT_ROOT>/data/demo_pdfs/user/)
- **Key Numbers & Findings**:
  - **1. Feature Extractor Architecture (`src/docsentry_extract.py`)**:
    - Reused upstream `thrember` classes directly: `GeneralFileInfo`, `ByteHistogram`, `ByteEntropyHistogram`, `StringExtractor`.
    - Implemented safe non-PE static parsing (`pe=None`), guaranteed magic-byte validation (`b'%PDF'`), empty file handling, and a strict 50 MB file size limit (`MAX_FILE_SIZE_BYTES = 52,428,800`).
    - Produces a $1 \times 658$ feature DataFrame matching the exact feature order of [`feature_names.json`](file:///<PROJECT_ROOT>/data/processed/feature_names.json).
  - **2. Pipeline Fidelity & Invariant Unit Tests (`tests/test_extract.py`)**:
    - **Pipeline Fidelity**: Streamed 200 raw test records from `data/raw/*.jsonl` through the extraction, column-dropping, and ordering pipeline; verified exact numerical equality against `X_test_tree.parquet` with **0.00e+00 maximum absolute difference**.
    - **Invariants**: Validated $(1, 658)$ output shape, exact feature order, zero `NaN`/`inf`, byte histogram sum to ~1.0, exact `general_size` match to byte count, header byte verification (`0x25 0x50 0x44 0x46`), and byte-level determinism.
    - **Test Suite Status**: All 8 unit tests in `tests/test_infer.py` and `tests/test_extract.py` pass with code 0.
  - **3. Synthetic Benchmark Evaluation**:
    | File | Size (Bytes) | Verdict | Calibrated $P(\text{mal})$ | Primary Positive Contributor | Primary Negative Contributor |
    | :--- | :--- | :--- | :--- | :--- | :--- |
    | `synthetic_a_minimal_blank.pdf` | 335 | `needs_review` | 0.4082 | `strings_numstrings` (+0.629) | `strings_regex_/URI` (-1.241) |
    | `synthetic_b_one_page_text.pdf` | 832 | `malicious` | 0.9808 | `strings_numstrings` (+0.822) | `strings_regex_/URI` (-1.178) |
    | `synthetic_c_20_page_report.pdf` | 3,684 | `malicious` | 0.7826 | `strings_numstrings` (+0.863) | `strings_regex_/URI` (-0.961) |
    | `synthetic_d_25_uris.pdf` | 7,147 | `malicious` | 0.9877 | `strings_regex_/URI` (+1.636) | `strings_regex_system` (-0.515) |
    | `synthetic_e_embedded_js.pdf` | 839 | `malicious` | 0.9953 | `strings_regex_javascript` (+1.883) | `strings_regex_/URI` (-0.896) |
    | `synthetic_f_large_5mb.pdf` | 5,500,811 | `needs_review` | 0.4082 | `byte_entropy_04_00` (+0.380) | `strings_regex_/URI` (-1.233) |
  - **4. User Corpus Evaluation**:
    - Scanned 9 real-world PDF documents placed into `data/demo_pdfs/user/`.
    - **0 false positive malicious verdicts**: 7 documents classified as `benign` and 2 documents routed to `needs_review` due to borderline indicator combinations.
  - **5. Documented Operational Vulnerabilities & Defenses**:
    - **Sub-100 KB Benign Penalty**: Pure text PDFs < 1 KB suffer false positives due to benchmark size correlation; mitigated by manual review triage.
    - **`/URI` Dominance**: 19.36% of model attribution rests on `/URI`, creating evasion risks for URL-less exploits and false alarms for link-heavy benign documents.
    - **Static Analysis Limits**: Blind to zero-day memory corruption shellcode within clean streams; requires pairing with dynamic sandboxing.

---

## Notebook 07: Real-PDF Demo Diagnostics & Out-Of-Distribution Triage (`notebooks/07_demo_diagnostics.ipynb`)
- **Phase**: Calibrator plateau root cause analysis, synthetic structural audit, train-split OOD warning envelope, and 9-file user document audit.
- **Completed**: 2026-11-24
- **Files Created / Updated**:
  - [`notebooks/07_demo_diagnostics.ipynb`](file:///<PROJECT_ROOT>/notebooks/07_demo_diagnostics.ipynb)
  - [`reports/figures/38_calibrator_plateau_steps.png`](file:///<PROJECT_ROOT>/reports/figures/38_calibrator_plateau_steps.png)
  - [`reports/figures/39_ood_percentiles_distribution.png`](file:///<PROJECT_ROOT>/reports/figures/39_ood_percentiles_distribution.png)
  - [`models/thresholds.json`](file:///<PROJECT_ROOT>/models/thresholds.json) (added `ood_thresholds`)
- **Key Numbers & Findings**:
  - **1. Feature Vector Dissimilarity & Calibrator Plateau**:
    - `synthetic_a` (335 B): Raw margin = -1.096793, raw $P = 0.250341$, calibrated $P = 0.408163$, size = 335 B, numstrings = 18, printables = 298, byte hist sum = 1.000000.
    - `synthetic_c` (3.7 KB): Raw margin = -0.208783, raw $P = 0.447993$, calibrated $P = 0.782609$, size = 3,684 B, numstrings = 108, printables = 3,549, byte hist sum = 1.000000.
    - `synthetic_f` (5.5 MB): Raw margin = -1.337071, raw $P = 0.207992$, calibrated $P = 0.408163$, size = 5,500,811 B, numstrings = 137,539, printables = 5,363,251, byte hist sum = 1.000000.
    - **Vector Comparison**: The feature vectors are **substantially different** (differing in 150/658 features between A and C, and 151/658 features between A and F).
    - **Calibrator Plateau Analysis**: Isotonic calibrator has a wide plateau step at $y = 0.408163$ covering raw probabilities $[0.200391, 0.303360)$ with a width of **0.102969** raw probability units.
    - Exactly **49 validation documents (0.49%)** and **140 test documents (1.17%)** land on this exact plateau.
    - Because the review band is $[0.290, 0.550]$, any document falling into this raw interval (including `synthetic_a`, `synthetic_f`, and `user_pdf_8.pdf`) is mapped to 0.4082 and safely routed to human review.
  - **2. Synthetic PDF Structural Analysis**:
    - `synthetic_c_20_page_report.pdf`: Declares 20 pages in `/Pages` catalog, but all 20 page dictionaries reference the exact same 145-byte content stream (`stream_id = 23`). It contains 20 pointer references to an empty page template.
    - `synthetic_f_large_5mb.pdf`: Contains 1 page of visible text plus an unreferenced 5,500,000-byte stream filled with repeating 40-byte ASCII padding (`b"DocSentry-Safe-Padding-Block-0123456789\n"`).
  - **3. Out-of-Distribution (OOD) Warning Envelope**:
    - Computed on **TRAIN split only**:
      - `general_size`: 0.5th percentile = **358.0 bytes**, 99.5th percentile = **30,602,208.0 bytes** (29.18 MB).
      - `strings_numstrings`: 0.5th percentile = **17.0 strings**, 99.5th percentile = **181,974.5 strings**.
    - **Validation Set**: 37 warned documents (0.37%). Unwarned accuracy = **98.48%** (9,962 docs), warned accuracy = **100.00%** (37 docs).
    - **Test Set**: 43 warned documents (0.36%). Unwarned accuracy = **95.38%** (11,957 docs), warned accuracy = **95.35%** (43 docs).
    - Added `ood_warning` boolean field to `src.docsentry_infer.predict` and `src.docsentry_extract.scan`.
  - **4. Audit of 9 Real User PDFs**:
    | File Name | Size (B) | Producer (First Bytes) | Verdict | Calibrated P | OOD Warning | Top 3 Contributors |
    | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
    | `user_pdf_1.pdf` | 112,048 | None | `benign` | 0.0101 | False | `strings_regex_/URI` (-1.464); `strings_printabledist_21` (-0.372); `strings_regex_https://` (-0.320) |
    | `user_pdf_2.pdf` | 674,202 | None | `benign` | 0.0074 | False | `strings_regex_/URI` (-1.374); `strings_numstrings` (-0.648); `strings_regex_https://` (-0.386) |
    | `user_pdf_3.pdf` | 483,771 | None | `needs_review` | 0.2984 | False | `strings_regex_/EmbeddedFile` (+1.448); `strings_printables` (-0.916); `strings_regex_/URI` (+0.733) |
    | `user_pdf_4.pdf` | 1,792,828 | None | `benign` | 0.0017 | False | `strings_regex_/URI` (-1.181); `strings_numstrings` (-0.671); `strings_printables` (-0.644) |
    | `user_pdf_5.pdf` | 90,018 | None | `benign` | 0.1220 | False | `strings_regex_/URI` (-1.598); `strings_regex_https://` (-0.416); `strings_printabledist_38` (-0.362) |
    | `user_pdf_6.pdf` | 336,479 | None | `benign` | 0.0041 | False | `strings_regex_/URI` (-1.375); `strings_numstrings` (-0.352); `strings_printabledist_38` (-0.313) |
    | `user_pdf_7.pdf` | 37,809 | (empty) | `benign` | 0.1220 | False | `strings_regex_/URI` (+1.077); `strings_printabledist_80` (-0.714); `strings_printabledist_68` (-0.642) |
    | `user_pdf_8.pdf` | 46,302 | None | `needs_review` | 0.4082 | False | `strings_regex_/URI` (+1.043); `strings_printabledist_80` (-0.699); `strings_regex_https://` (+0.654) |
    | `user_pdf_9.pdf` | 38,799 | (empty) | `benign` | 0.0258 | False | `strings_regex_/URI` (-1.155); `strings_numstrings` (+0.369); `strings_printabledist_20` (+0.336) |
    - **Review Triage Rationale**:
      - `user_pdf_3.pdf`: Calibrated $P = 0.2984$ lands in review band $[0.290, 0.550]$. Driven by strong positive push from embedded attachments (`strings_regex_/EmbeddedFile` +1.448) and links (`strings_regex_/URI` +0.733), counterbalanced by negative push from textual bulk (`strings_printables` -0.916).
      - `user_pdf_8.pdf`: Raw probability is 0.2561, landing on the calibrator plateau $[0.2004, 0.3034) \to 0.4082$, inside the review band $[0.290, 0.550]$. Positive pushes from contact links (`strings_regex_/URI` +1.043) and URL schemes (`strings_regex_https://` +0.654) in a small file (46.3 KB) are counterbalanced by character distributions (`strings_printabledist_80` -0.699). Review triage avoids an automated false alarm.

---

## Production Web Application & Test Verification (`app/`, `tests/test_api.py`, `run_app.bat`)
- **Phase**: FastAPI REST API, zero-CDN accessible UI, 17 automated tests, and headless screenshot verification.
- **Completed**: 2026-11-24
- **Files Created / Updated**:
  - [`app/main.py`](file:///<PROJECT_ROOT>/app/main.py)
  - [`app/static/index.html`](file:///<PROJECT_ROOT>/app/static/index.html)
  - [`app/static/style.css`](file:///<PROJECT_ROOT>/app/static/style.css)
  - [`app/static/app.js`](file:///<PROJECT_ROOT>/app/static/app.js)
  - [`tests/test_api.py`](file:///<PROJECT_ROOT>/tests/test_api.py)
  - [`run_app.bat`](file:///<PROJECT_ROOT>/run_app.bat)
  - [`README.md`](file:///<PROJECT_ROOT>/README.md)
  - [`requirements.txt`](file:///<PROJECT_ROOT>/requirements.txt)
  - [`reports/figures/ui_landing.png`](file:///<PROJECT_ROOT>/reports/figures/ui_landing.png)
- **Key Numbers & Findings**:
  - **1. Production Server Architecture**:
    - Endpoints: `GET /health`, `GET /model-info`, `POST /scan`.
    - Pure in-memory processing up to 20 MB; zero permanent file storage; sanitized filenames; magic-byte validation (`b'%PDF'`).
    - Decodes all 658 features into plain-English labels and builds factual plain-language explanations.
    - CORS restricted to localhost; binds to `127.0.0.1`.
  - **2. Automated Test Suite**:
    - Ran all 17 tests across `tests/test_infer.py`, `tests/test_extract.py`, and `tests/test_api.py`.
    - **Status**: 17 / 17 passed (`OK`) in 6.32s with zero failures.

---

## UI Redesign, Honest Wording, Model Card & Reproducibility (`2026-11-25`)
- **Phase**: Complete visual redesign (zero blue hues, WCAG contrast compliance), SVG chart & gauge fixes, honest wording & `/URI` dependence evidence note, `MODEL_CARD.md`, and `report_assets/` bundler.
- **Completed**: 2026-11-25
- **Files Created / Updated**:
  - [`app/static/index.html`](file:///<PROJECT_ROOT>/app/static/index.html)
  - [`app/static/style.css`](file:///<PROJECT_ROOT>/app/static/style.css)
  - [`app/static/app.js`](file:///<PROJECT_ROOT>/app/static/app.js)
  - [`app/main.py`](file:///<PROJECT_ROOT>/app/main.py)
  - [`reports/uri_dependence.json`](file:///<PROJECT_ROOT>/reports/uri_dependence.json)
  - [`MODEL_CARD.md`](file:///<PROJECT_ROOT>/MODEL_CARD.md)
  - [`scripts/make_report_assets.py`](file:///<PROJECT_ROOT>/scripts/make_report_assets.py)
  - [`scripts/check_contrast.py`](file:///<PROJECT_ROOT>/scripts/check_contrast.py)
  - [`scripts/capture_ui_screenshots.py`](file:///<PROJECT_ROOT>/scripts/capture_ui_screenshots.py)
  - [`requirements.txt`](file:///<PROJECT_ROOT>/requirements.txt)
  - [`README.md`](file:///<PROJECT_ROOT>/README.md)
  - [`report_assets/index.md`](file:///<PROJECT_ROOT>/report_assets/index.md)
- **Key Highlights & Verification**:
  - **1. Visual Redesign & Zero Blue**: Replaced navy/blue palette with CSS custom properties (`#141414`/`#1D1D1D` dark, `#F7F5F2`/`#FFFFFF` light), amber `#E0A030` / `#1B1B1A` focus rings, and saturated verdict colors only. Verified 0 blue hex/HSL hues remain.
  - **2. Contrast Compliance**: Verified WCAG AA compliance ($\ge 4.5:1$ text, $\ge 3.0:1$ UI components) across both themes via `scripts/check_contrast.py`.
  - **3. Layout & Chart Fixes**: Placed result card above upload zone post-scan, made calibrated probability the largest tabular number, moved gauge needle bubble below title clearance, fixed latency `word-break`, and placed SVG numeric labels outside bar ends with wrapped labels and keyboard-focusable tooltips.
  - **4. Honest Wording & `/URI` Evidence Note**: Updated execution/quarantine/calibration/footer/limitation wording; generated `reports/uri_dependence.json` (`62.23%` recall for `/URI == 0` malicious PDFs) and wired dynamic evidence notes into `/scan`.
  - **5. Headless Screenshots**: Captured 23 responsive dark/light screenshots (`reports/figures/ui_*.png`) using strictly synthetic PDFs.
  - **6. Reproducibility & Model Card**: Created `MODEL_CARD.md` citing all file-sourced metrics, pinned `signify==0.7.1` rationale in `requirements.txt`, documented full `01`–`07` reproduction in `README.md`, and bundled 48 figures + 2 CSVs into `report_assets/`.
    - Verified schema completeness, non-PDF rejection (400), empty file rejection (400), size cap (413), filename traversal stripping (`../`), extraction fidelity match to `scan()`, and zero leaked temp files.
  - **3. HTTP API Verification & Headless Screenshots**:
    - Started uvicorn server on loopback port 8000.
    - Scanned all 3 synthetic PDFs and all 9 user PDFs through HTTP `POST /scan`; 12 / 12 verdicts matched expected outputs identically.
    - Captured full-page headless UI screenshot in [`reports/figures/ui_landing.png`](file:///<PROJECT_ROOT>/reports/figures/ui_landing.png) via Microsoft Edge headless mode.

---

## Printed Technical Form UI Redesign & Model Card Corrections (`2026-11-26`)
- **Phase**: Paper/ink/mint/peach printed lab-report UI redesign (`Space Grotesk` + `IBM Plex Mono` offline `@font-face`), neutral regex labels, calibrated `/URI` evidence note (`71.32%`), and recomputed `MODEL_CARD.md` fixes.
- **Completed**: 2026-11-26
- **Key Changes**:
  - **UI & Fonts**: Added local `Space Grotesk` and `IBM Plex Mono` `.woff2` fonts in `app/static/fonts/`, warm paper dotted-grid canvas (`#F1EFE6` light / `#121210` dark), black label bars, ticker strip (`prefers-reduced-motion` safe), mint upload & peach details panels, clickable session history, accessible hidden `<table>` alternatives for SVG charts, and dynamic `/model-info` rendering.
  - **Neutral Labels & Calibrated `/URI` Note**: Updated `app/main.py` regex labels to `"Occurrences of the word '<word>'"` with behaviour disclaimer tooltip; switched `/URI == 0` evidence note to calibrated-threshold recall (`71.32%`), keeping `62.23%` default-threshold recall in the Model section.
  - **Model Card Fixes**: Recomputed 6-family SHAP shares (`38.3%`, `25.2%`, `21.2%`, `8.3%`, `4.7%`, `2.4%` — fixing the `0.0%` `strings_printabledist_` prefix bug), verified error breakdowns (`151` validation, `554` test), corrected TLSH overlap to validation-vs-test (week 45 vs week 63), labeled validation Brier/ECE as in-sample, verified `/URI > 0` calibrated FPR (`72/1,275 = 5.65%`), and added the OOD sanity-check paragraph.
  - **Screenshots & Assets**: Captured 17 `ui_v2_*.png` screenshots (synthetic PDFs only) and re-ran `scripts/make_report_assets.py` (65 figures + 2 CSVs).
  - **Mobile Overflow Fix, Copy Polish & Reconciled Numbers (`ui_v3`)**:
    - Fixed 360px/390px horizontal overflow at the source by removing `overflow-x: hidden` from `body`, adding `min-width: 0` on flex/grid children, constraining `.sr-only` tables (`max-width: 1px; max-height: 1px`), and capping `.ticker-strip` / `.verdict-badge` widths. Verified `0` overflow across all 40 Playwright combinations (`360/390/768/1280px` × `light/dark` × `empty/benign/review/malicious/ood`).
    - Stripped `[Notice: ...]` from UI reason text (replaced by reworded `OUT OF RANGE` banner with `/model-info` envelope), renamed sample buttons (`Sample: harmless 20-page report`, `Sample: harmless 5.5 MB padded file`), added `text-wrap: balance/pretty`, and added desktop-only hero starburst SVG.
    - Reconciled Notebook 05 Cell 16 (`strings_printabledist_` prefix fix, regenerating Figure 35) with `MODEL_CARD.md` and `reports/model_card_metrics.json` (`38.26%`, `25.17%`, `21.22%`, `8.32%`, `4.65%`, `2.38%` = `100.00%`).
    - Captured sliced `ui_v3_*.png` full-page screenshots (`<= 1400 px` height) and 7 section screenshots.
  - **UI Review Fixes, Notebook 08 (`/URI` Counterfactual & Ablations) & Model Card Finalization**:
    - Moved top ticker above header (`32 px`, `13 px` mono, dark card hairline surface), fixed `< 640 px` mobile stacked SHAP/family charts (`width >= 4 px` verified), fixed `/model-info` `inside_band`/`outside_band` error readout, added `HISTORY` label bar & verified real `#file-input` 3-row reload, added 3 distinct surface levels + inside-bar gauge labels, switched all displayed sizes to decimal MB (`1 MB = 1,000,000 B`) and `20 MiB` upload cap, and updated OOD banner wording.
    - Created and executed [`notebooks/08_uri_counterfactual.ipynb`](file:///<PROJECT_ROOT>/notebooks/08_uri_counterfactual.ipynb): verified `554` test errors & `71.32%` `/URI==0` recall; ran `/URI=0,1,5,25` counterfactuals (`1,814` link-bearing malicious files drop out of `malicious` under `/URI=0`); plotted Figures 40–41; ran 3 retrained XGBoost ablations under `models/ablation/` (`0.9451` -> `0.9476` no `/URI` -> `0.9388` no regex); ran domain-shift check (`reports/domain_shift_demo.csv`).
    - Updated `MODEL_CARD.md` with plain-text formatting (zero `$...$`), operating points table (`0.50` vs `0.4083`), HGB overlap CI, counterfactual/ablation section, and decimal units.
  - **Small Fix Pass (`2026-11-26`)**:
    - Redesigned gauge labels cleanly below the bar (`BENIGN 0–29%`, `REVIEW 29–55%`, `MALICIOUS 55–100%`) with zero text inside `.gauge-track` and verified zero overlap/collision across `360/390/768/1280 px` in both themes.
    - Verified `.ticker-strip` dark theme uses `--card` (`rgb(28, 28, 25)`) with `--ink` text (`rgb(241, 239, 230)`).
    - Replaced `"minimal suspicious indicators"` with `"small opposing signals"` in `app/main.py`.
    - Fixed Notebook 08's `"What this shows"` cell (explicitly separating `t = 0.4083` recall fall from `> 0.550` malicious-verdict transitions `1,619` `needs_review` / `195` `benign`, and stating no F1 loss without `/URI`) and added the domain-shift summary to `MODEL_CARD.md`.
    - **Domain-Shift & SHAP Explanation Fix (`2026-11-26`)**:
      - Fixed the domain-shift conclusion in `notebooks/08_uri_counterfactual.ipynb` (computed via f-strings from `reports/domain_shift_demo.csv`) and `MODEL_CARD.md`: corrected `user_pdf_1..9` spread (`9.20`th–`74.29`th size percentile, 5/9 below 25th; `15.10`th–`73.66`th string count; `11.24`th–`91.53`th entropy), separated `synthetic_f` (`87.99`th size, `98.41`th string count, `0.26`th entropy) from `synthetic_a`–`e` (`0.00`th–`4.80`th size), and documented the `uri_pct_rank = 82.84` zero-link tie plateau.
      - Ran `scripts/analyze_demo_shap.py` for the 6 synthetic PDFs + `user_pdf_3.pdf` and `user_pdf_8.pdf`, added the top-5 SHAP contributor table to `MODEL_CARD.md`, noted the 3 files (`synthetic_a`, `synthetic_f`, `user_pdf_8`) on the `0.4082` calibrator plateau, and replaced `"keys on link counts and keywords"` in `app/static/index.html` and `README.md` with evidence-based wording.
    - **Demo Note Refinement & Fresh-Clone Smoke Test (`2026-11-26`)**:
      - Verified no entropy feature appears in the top SHAP contributors for `synthetic_a`, `synthetic_b`, or `synthetic_c`; removed `"low entropy"` as a stated cause in `app/static/index.html` `.sample-note`, matched upload-panel units (`20 MiB (20.97 MB)` and `5.25 MiB (5.5 MB)`), and kept `.sample-note` to `<= 3` lines at `390 px`.
      - Ran a fresh-clone smoke test in `C:\temp\docsentry_check` from the local repo with a clean venv: `pip install -r requirements.txt` succeeded, `tests/test_api.py` (11/11) passed, and `GET /health`, `GET /model-info`, and `POST /scan` returned HTTP 200; confirmed `test_extract.py` and `test_infer.py` require git-ignored `data/processed/X_test_tree.parquet`.
      - Updated `README.md` with the complete folder tree, fresh-clone vs full-reproducibility test commands, and Notebook `08` documentation.



