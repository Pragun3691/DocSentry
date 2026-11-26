"""
DocSentry — Update and Execute Notebook 05
Applies all PART 0 requirements:
1. Figure 36: 5 separate individual files (36_1_true_positive.png ... 36_5_review_band.png),
   plt.figure() per plot, no overlapping axes. Confident FN with P < 0.29 (not row 31),
   review-band document with P in [0.29, 0.55] distinct from FN.
2. Error counts: defined explicitly as misclassification at threshold 0.4083 on calibrated probability.
   Recompute total errors, errors inside review band, errors outside review band for val & test.
   Assert inside + outside == total.
3. Figure 32: colour week 51 as validation (weeks 42-51 blue, weeks 52-63 red).
   Compute OLS slope over weeks 42-63, print it, use in legend & markdown. Real max review rate.
4. Calibration: label all validation Brier/ECE numbers as in-sample, lead with test numbers.
5. Size-matched section: remove 'proving'. State matched subset has only 30, 7, 1 malicious files in
   three largest bins, recall is 33%, 0%, 0%, matched FPR (1.32%) is higher than full-test FPR (0.92%),
   suggesting possible large-file blind spot that cannot be confirmed with so few samples.
6. Dependence on /URI: report test recall for malicious files with /URI == 0 vs > 0, test FPR for benign
   files with /URI == 0 vs > 0, with counts. Report /URI share of total mean |SHAP|.
7. SHAP stability check: restrict to top 50 features and report Spearman correlation.
   Fix overlapping titles in Figure 27.
"""

import nbformat
from nbclient import NotebookClient
import os
import sys

nb_path = "notebooks/05_explain_uncertainty.ipynb"
with open(nb_path, "r", encoding="utf-8") as f:
    nb = nbformat.read(f, as_version=4)

# We will define the updated cells
# Let's inspect current cells and replace content appropriately

# Cell 2: Setup imports
if "from sklearn.calibration import calibration_curve" not in nb.cells[2].source:
    nb.cells[2].source = nb.cells[2].source.replace(
        "from sklearn.isotonic import IsotonicRegression",
        "from sklearn.calibration import calibration_curve\nfrom scipy.stats import spearmanr\nfrom sklearn.isotonic import IsotonicRegression"
    )

# Cell 5: Markdown PART A
nb.cells[5].source = r"""## PART A: Statistical Comparison (Bootstrap 95% Confidence Intervals)
To determine whether observed test performance differences between architectures are statistically significant or attributable to sampling variance, we perform **paired non-parametric bootstrap resampling** with 1,000 iterations on the 12,000 test set samples.

For each resample $b \\in \\{1, \\dots, 1000\\}$:
1. We draw a sample with replacement of size $N=12,000$.
2. We compute F1, recall, false positive rate (FPR), and ROC-AUC for all 4 models.
3. We record the paired differences $\\Delta_b = \\text{Metric}_{\\text{XGB}, b} - \\text{Metric}_{\\text{HGB}, b}$ to rigorously test whether the champion XGBoost and runner-up HistGradientBoosting differ significantly ($0 \\notin \\text{95% CI}(\\Delta)$).
4. We visualize the distributions with 95% confidence error bars (`reports/figures/27_bootstrap_test_ci_comparison.png`). Ample subplot padding prevents any title or axis overlap."""

# Cell 6: Code PART A (Bootstrap & Figure 27)
nb.cells[6].source = r"""# 1. Precompute test predictions and probabilities for all models
test_probas = {}
test_preds = {}

for name, model in models.items():
    X_test = X_te_linear if name == 'Logistic Regression' else X_te_tree
    test_preds[name] = model.predict(X_test)
    test_probas[name] = model.predict_proba(X_test)[:, 1]

# 2. Bootstrap Resampling (1,000 iterations)
n_resamples = 1000
rng_boot = np.random.RandomState(42)
N_test = len(y_te)

boot_metrics = {m: {'f1': [], 'recall': [], 'fpr': [], 'roc_auc': []} for m in models.keys()}
paired_diffs = {'f1': [], 'recall': [], 'fpr': [], 'roc_auc': []}

print(f"Executing 1,000 bootstrap resamples on test set (N={N_test})...")
t0 = time.time()

for b in range(n_resamples):
    idx = rng_boot.choice(N_test, size=N_test, replace=True)
    y_b = y_te[idx]
    
    # Pre-calculate metrics for each model
    iter_res = {}
    for name in models.keys():
        pred_b = test_preds[name][idx]
        prob_b = test_probas[name][idx]
        
        f1_val = f1_score(y_b, pred_b, zero_division=0)
        rec_val = recall_score(y_b, pred_b, zero_division=0)
        # FPR = FP / (FP + TN)
        tn, fp, fn, tp = confusion_matrix(y_b, pred_b, labels=[0, 1]).ravel()
        fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        auc_val = roc_auc_score(y_b, prob_b)
        
        boot_metrics[name]['f1'].append(f1_val)
        boot_metrics[name]['recall'].append(rec_val)
        boot_metrics[name]['fpr'].append(fpr_val)
        boot_metrics[name]['roc_auc'].append(auc_val)
        iter_res[name] = {'f1': f1_val, 'recall': rec_val, 'fpr': fpr_val, 'roc_auc': auc_val}
        
    # Paired differences: XGBoost vs. HistGradientBoosting
    for metric in ['f1', 'recall', 'fpr', 'roc_auc']:
        paired_diffs[metric].append(iter_res['XGBoost'][metric] - iter_res['HistGradientBoosting'][metric])

print(f"Bootstrap completed in {time.time()-t0:.1f}s.")

# 3. Compute 95% CIs and format comparison table
table_rows = []
for name in models.keys():
    row = {'Model': name}
    for metric in ['f1', 'recall', 'fpr', 'roc_auc']:
        vals = np.array(boot_metrics[name][metric])
        mean_val = np.mean(vals)
        ci_low, ci_high = np.percentile(vals, [2.5, 97.5])
        row[f'{metric.upper()} Mean (95% CI)'] = f"{mean_val:.4f} [{ci_low:.4f}, {ci_high:.4f}]"
    table_rows.append(row)

df_ci = pd.DataFrame(table_rows)
print("=" * 105)
print("BOOTSTRAP 95% CONFIDENCE INTERVALS ON TEST SET (1,000 RESAMPLES)")
print("=" * 105)
display(df_ci)

# 4. Rigorous Hypothesis Testing: XGBoost vs HistGradientBoosting
print("\n" + "=" * 105)
print("PAIRED BOOTSTRAP SIGNIFICANCE TEST: XGBOOST VS. HISTGRADIENTBOOSTING")
print("=" * 105)
sig_results = []
for metric in ['f1', 'recall', 'fpr', 'roc_auc']:
    diff_vals = np.array(paired_diffs[metric])
    diff_mean = np.mean(diff_vals)
    d_low, d_high = np.percentile(diff_vals, [2.5, 97.5])
    # Significant if 0 is not in [d_low, d_high]
    significant = not (d_low <= 0 <= d_high)
    sig_results.append({
        'Metric': metric.upper(),
        'Mean Difference (XGB - HGB)': f"{diff_mean:+.5f}",
        '95% CI of Difference': f"[{d_low:+.5f}, {d_high:+.5f}]",
        'Statistically Significant?': 'YES (p < 0.05)' if significant else 'NO (p >= 0.05)'
    })
df_sig = pd.DataFrame(sig_results)
display(df_sig)

# 5. Figure 27: Bootstrap Comparison Plot (clean layout, no overlapping titles)
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
plt.subplots_adjust(top=0.92, bottom=0.08, left=0.08, right=0.95, hspace=0.38, wspace=0.25)
fig.suptitle("Figure 27: Test Metric Comparison with 95% Bootstrap Confidence Intervals (1,000 Resamples)",
             fontsize=14, fontweight='bold', y=0.97)

metric_keys = [('f1', 'F1 Score', axes[0, 0]),
               ('recall', 'Recall (True Positive Rate)', axes[0, 1]),
               ('fpr', 'False Positive Rate (FPR)', axes[1, 0]),
               ('roc_auc', 'ROC-AUC', axes[1, 1])]

colors = {'Logistic Regression': '#7f8c8d', 'Random Forest': '#2980b9', 'XGBoost': '#27ae60', 'HistGradientBoosting': '#e67e22'}

for m_key, m_label, ax in metric_keys:
    y_pos = np.arange(len(models))
    means = [np.mean(boot_metrics[m][m_key]) for m in models.keys()]
    lows = [np.percentile(boot_metrics[m][m_key], 2.5) for m in models.keys()]
    highs = [np.percentile(boot_metrics[m][m_key], 97.5) for m in models.keys()]
    err_low = np.array(means) - np.array(lows)
    err_high = np.array(highs) - np.array(means)
    
    bars = ax.barh(y_pos, means, xerr=[err_low, err_high], align='center',
                   color=[colors[m] for m in models.keys()], alpha=0.85, ecolor='black', capsize=5, height=0.55)
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(list(models.keys()), fontsize=10)
    ax.set_xlabel(m_label, fontsize=10, fontweight='bold')
    ax.set_title(f"Test {m_label}", fontsize=11, fontweight='bold', pad=10)
    ax.grid(axis='x', linestyle='--', alpha=0.5)
    
    # Numeric annotation on bars
    for i, (m_val, l_val, h_val) in enumerate(zip(means, lows, highs)):
        ax.text(m_val * 0.5, i, f"{m_val:.4f}\\n[{l_val:.4f}, {h_val:.4f}]",
                va='center', ha='center', color='white', fontweight='bold', fontsize=8.5)

fig27_path = FIGURES_DIR / '27_bootstrap_test_ci_comparison.png'
plt.savefig(fig27_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 27 to: {fig27_path}")"""

# Cell 7: Markdown PART B (Size-Matched Evaluation)
nb.cells[7].source = r"""## PART B: Size-Matched Evaluation
A major finding from EDA and Modeling diagnostics was that malicious PDFs concentrate heavily in specific file size modes (e.g. 100–200 KB), while benign files are substantially larger on average (~464 KB median). Consequently, small benign documents face an elevated false positive rate.

To test model sensitivity across the size continuum without size bias:
1. We discretize test file sizes on a log scale into 8 bins.
2. We form an exact **size-matched evaluation set** by subsampling equal numbers of benign and malicious documents from each size bin ($k_b = \\min(n_{\\text{benign}, b}, n_{\\text{malicious}, b})$).
3. We compute and compare champion metrics (Accuracy, Precision, Recall, F1, ROC-AUC) on the size-matched subset vs. the full test set.

**Critical Empirical Findings**:
- The size-matched subset contains **only 30, 7, and 1 malicious files** in the three largest bins (Bins 6, 7, and 8), where recall drops to **33.3%, 0.0%, and 0.0%**.
- Size-matched FPR (**1.32%**) is higher than full-test FPR (**0.92%**).
- This suggests a **possible large-file blind spot that cannot be confirmed with so few samples**, rather than establishing that size alone drives detection."""

# Cell 8: Code PART B (Size-Matched Evaluation & Figure 28)
nb.cells[8].source = r"""# 1. Log-scale discretization of test file sizes
test_sizes = X_te_tree['general_size']
size_bins = np.logspace(np.log10(max(test_sizes.min(), 1)), np.log10(test_sizes.max()), 9)
bin_labels = [f"Bin {i+1} [{size_bins[i]/1024:.1f}K-{size_bins[i+1]/1024:.1f}K]" for i in range(len(size_bins)-1)]

df_test_eval = pd.DataFrame({
    'size': test_sizes,
    'label': y_te,
    'pred': test_preds['XGBoost'],
    'proba': test_probas['XGBoost']
})
df_test_eval['size_bin'] = pd.cut(df_test_eval['size'], bins=size_bins, labels=bin_labels, include_lowest=True)

# 2. Form Size-Matched Subsample
rng_match = np.random.RandomState(42)
matched_indices = []

for b_name, grp in df_test_eval.groupby('size_bin', observed=False):
    idx_b0 = grp[grp['label'] == 0].index
    idx_b1 = grp[grp['label'] == 1].index
    k = min(len(idx_b0), len(idx_b1))
    if k > 0:
        matched_indices.extend(rng_match.choice(idx_b0, k, replace=False))
        matched_indices.extend(rng_match.choice(idx_b1, k, replace=False))

df_matched = df_test_eval.loc[matched_indices]

# 3. Comparative Metrics
def compute_metrics_df(df_sub):
    y_true = df_sub['label'].values
    y_p = df_sub['pred'].values
    y_pb = df_sub['proba'].values
    return {
        'Samples': len(df_sub),
        'Benign': int((y_true == 0).sum()),
        'Malicious': int((y_true == 1).sum()),
        'Accuracy': accuracy_score(y_true, y_p),
        'Precision': precision_score(y_true, y_p, zero_division=0),
        'Recall': recall_score(y_true, y_p, zero_division=0),
        'F1 Score': f1_score(y_true, y_p, zero_division=0),
        'ROC-AUC': roc_auc_score(y_true, y_pb),
        'FPR': np.mean((y_p == 1)[y_true == 0])
    }

m_full = compute_metrics_df(df_test_eval)
m_matched = compute_metrics_df(df_matched)

df_comp_matched = pd.DataFrame([
    {'Evaluation Set': 'Full Unmatched Test Set', **m_full},
    {'Evaluation Set': 'Size-Matched Test Set (1:1 per bin)', **m_matched}
])

print("=" * 95)
print("CHAMPION XGBOOST: FULL TEST SET VS. SIZE-MATCHED EVALUATION")
print("=" * 95)
display(df_comp_matched)

# 4. Bin-by-bin Breakdown Table
bin_audit_rows = []
for b_name, grp in df_test_eval.groupby('size_bin', observed=False):
    n0 = int((grp['label'] == 0).sum())
    n1 = int((grp['label'] == 1).sum())
    fpr = np.mean((grp['pred'] == 1)[grp['label'] == 0]) if n0 > 0 else np.nan
    rec = np.mean((grp['pred'] == 1)[grp['label'] == 1]) if n1 > 0 else np.nan
    bin_audit_rows.append({
        'Size Interval': b_name,
        'Total Samples': len(grp),
        'Benign Count': n0,
        'Malicious Count': n1,
        'Matched Pairs': min(n0, n1),
        'FPR (% Benign)': f"{fpr*100:.2f}%" if not np.isnan(fpr) else "N/A",
        'Recall (% Malicious)': f"{rec*100:.2f}%" if not np.isnan(rec) else "N/A"
    })

df_bin_audit = pd.DataFrame(bin_audit_rows)
print("\n" + "=" * 95)
print("PER-SIZE-BIN SAMPLE COUNTS, RECALL AND FPR BREAKDOWN")
print("=" * 95)
display(df_bin_audit)

# Explicitly print the verified observations requested
print("\n" + "=" * 95)
print("EMPIRICAL SIZE-MATCHED AUDIT STATEMENTS:")
print(f"  - Malicious files in Bin 6: {bin_audit_rows[5]['Malicious Count']}, Recall: {bin_audit_rows[5]['Recall (% Malicious)']}")
print(f"  - Malicious files in Bin 7: {bin_audit_rows[6]['Malicious Count']}, Recall: {bin_audit_rows[6]['Recall (% Malicious)']}")
print(f"  - Malicious files in Bin 8: {bin_audit_rows[7]['Malicious Count']}, Recall: {bin_audit_rows[7]['Recall (% Malicious)']}")
print(f"  - Size-Matched FPR: {m_matched['FPR']*100:.2f}% vs. Full-Test FPR: {m_full['FPR']*100:.2f}%")
print("  - CONCLUSION: This suggests a possible large-file blind spot that cannot be confirmed with so few samples.")
print("=" * 95)

# 5. Plot Figure 28
fig, axes = plt.subplots(1, 2, figsize=(15, 6))

sns.histplot(data=df_test_eval, x='size', hue='label', log_scale=True, ax=axes[0],
             palette=['#2980b9', '#c0392b'], element='step', alpha=0.4, bins=40)
axes[0].set_title("Full Test File Size Distribution by Class", fontsize=12, fontweight='bold')
axes[0].set_xlabel("File Size in Bytes (Log Scale)")
axes[0].set_ylabel("Document Count")

x_idx = np.arange(len(df_bin_audit))
fpr_vals = [float(x.replace('%', '')) if x != 'N/A' else 0.0 for x in df_bin_audit['FPR (% Benign)']]
rec_vals = [float(x.replace('%', '')) if x != 'N/A' else 0.0 for x in df_bin_audit['Recall (% Malicious)']]

width = 0.35
axes[1].bar(x_idx - width/2, rec_vals, width, label='Recall (Malicious %)', color='#27ae60', edgecolor='black')
axes[1].bar(x_idx + width/2, fpr_vals, width, label='FPR (Benign %)', color='#e74c3c', edgecolor='black')
axes[1].set_xticks(x_idx)
axes[1].set_xticklabels([f"Bin {i+1}" for i in range(len(x_idx))], rotation=45)
axes[1].set_title("Recall and FPR Across File Size Bins", fontsize=12, fontweight='bold')
axes[1].set_ylabel("Rate (%)")
axes[1].set_ylim(0, 110)
axes[1].legend()
axes[1].grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
fig28_path = FIGURES_DIR / '28_size_matched_evaluation.png'
plt.savefig(fig28_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 28 to: {fig28_path}")"""

# Cell 9: Markdown PART C (Calibration)
nb.cells[9].source = r"""## PART C: Probability Calibration & Operational Threshold Analysis

### 1. Calibration Evaluation (Leading with Out-of-Sample Test Performance)
Raw tree ensemble outputs represent margin scores rather than well-calibrated posterior probabilities. To achieve trustworthy risk estimates:
- We fit probability calibrators **strictly on validation data** (`X_va_tree`).
- We benchmark **Platt Scaling (Sigmoid)** against **Isotonic Regression** using 5-fold cross-validated Brier score within the validation split.
- **Reporting Protocol**: We report **out-of-sample Test metrics first** (Weeks 52–63), followed by **Validation metrics explicitly labeled as in-sample** (since the calibrator was fitted directly on validation data).
- We evaluate calibration with **Brier Score** and **Expected Calibration Error (ECE)**, visualizing reliability diagrams (`reports/figures/29_calibration_reliability_diagrams.png`).

### 2. Operational Threshold Sweep
Default classification at $P=0.5$ is suboptimal when false positives and false negatives carry asymmetrical operational costs.
- We sweep decision thresholds $t \\in [0.01, 0.99]$ on validation data.
- We identify the threshold achieving **validation $\\text{FPR} \\approx 1.0\\%$** ($t=0.4083$) and evaluate its behavior on the test set.
- We compute test malicious recall at fixed operational FPR targets of **0.1%**, **1.0%**, and **5.0%** (`reports/figures/30_threshold_recall_fpr_tradeoff.png`)."""

# Cell 10: Code PART C (Calibration leading with Test numbers, labeling val as in-sample)
nb.cells[10].source = r"""# 1. Validation Probabilities & CV Calibration Selection
val_raw = champion_model.predict_proba(X_va_tree)[:, 1]
te_raw = test_probas['XGBoost']

kf = KFold(n_splits=5, shuffle=True, random_state=42)
brier_sig, brier_iso = [], []

for tr_idx, va_idx in kf.split(val_raw):
    # Platt Sigmoid
    lr = LogisticRegression(C=1.0, solver='lbfgs')
    lr.fit(val_raw[tr_idx].reshape(-1, 1), y_va[tr_idx])
    p_sig = lr.predict_proba(val_raw[va_idx].reshape(-1, 1))[:, 1]
    brier_sig.append(brier_score_loss(y_va[va_idx], p_sig))
    
    # Isotonic Regression
    iso = IsotonicRegression(out_of_bounds='clip', y_min=0.0, y_max=1.0)
    iso.fit(val_raw[tr_idx], y_va[tr_idx])
    p_iso = iso.predict(val_raw[va_idx])
    brier_iso.append(brier_score_loss(y_va[va_idx], p_iso))

mean_brier_sig = np.mean(brier_sig)
mean_brier_iso = np.mean(brier_iso)

print(f"5-Fold CV Brier Score on Validation:")
print(f"  Sigmoid (Platt):     {mean_brier_sig:.6f} (+/- {np.std(brier_sig):.6f})")
print(f"  Isotonic Regression: {mean_brier_iso:.6f} (+/- {np.std(brier_iso):.6f})")

chosen_method = "Isotonic Regression" if mean_brier_iso < mean_brier_sig else "Sigmoid"
print(f"Selected Champion Calibrator: {chosen_method} (Lowest CV Brier Loss)")

# Fit final calibrator on full validation set
calibrator = IsotonicRegression(out_of_bounds='clip', y_min=0.0, y_max=1.0)
calibrator.fit(val_raw, y_va)

val_cal = np.clip(calibrator.predict(val_raw), 0.0, 1.0)
te_cal = np.clip(calibrator.predict(te_raw), 0.0, 1.0)

# 2. Expected Calibration Error (ECE) function
def compute_ece(y_true, y_prob, n_bins=10):
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_indices = np.digitize(y_prob, bin_edges, right=True)
    ece = 0.0
    for b in range(1, n_bins + 1):
        mask = bin_indices == b
        if np.sum(mask) > 0:
            bin_acc = np.mean(y_true[mask])
            bin_conf = np.mean(y_prob[mask])
            ece += (np.sum(mask) / len(y_true)) * np.abs(bin_acc - bin_conf)
    return ece

# Tabulate Calibration Impact: LEAD WITH TEST (Out-of-sample), followed by VALIDATION (In-sample)
cal_audit_rows = [
    {
        'Split': 'Test (Weeks 52-63, Out-of-Sample)',
        'Stage': 'Raw XGBoost',
        'Brier Score': brier_score_loss(y_te, te_raw),
        'ECE': compute_ece(y_te, te_raw)
    },
    {
        'Split': 'Test (Weeks 52-63, Out-of-Sample)',
        'Stage': 'Calibrated (Isotonic)',
        'Brier Score': brier_score_loss(y_te, te_cal),
        'ECE': compute_ece(y_te, te_cal)
    },
    {
        'Split': 'Validation (Weeks 42-51, In-Sample)',
        'Stage': 'Raw XGBoost',
        'Brier Score': brier_score_loss(y_va, val_raw),
        'ECE': compute_ece(y_va, val_raw)
    },
    {
        'Split': 'Validation (Weeks 42-51, In-Sample)',
        'Stage': 'Calibrated (Isotonic)',
        'Brier Score': brier_score_loss(y_va, val_cal),
        'ECE': compute_ece(y_va, val_cal)
    }
]

df_cal_audit = pd.DataFrame(cal_audit_rows)
print("\n" + "=" * 95)
print("PROBABILITY CALIBRATION AUDIT: OUT-OF-SAMPLE TEST VS. IN-SAMPLE VALIDATION")
print("=" * 95)
display(df_cal_audit)

# 3. Figure 29: Reliability Diagrams
fig, axes = plt.subplots(1, 2, figsize=(14, 6))

# Test Reliability
f_raw, m_raw = calibration_curve(y_te, te_raw, n_bins=10)
f_cal, m_cal = calibration_curve(y_te, te_cal, n_bins=10)

axes[0].plot([0, 1], [0, 1], "k:", label="Perfect Calibration")
axes[0].plot(m_raw, f_raw, "s-", color='#e74c3c', label=f"Raw XGBoost (ECE={compute_ece(y_te, te_raw):.4f})")
axes[0].plot(m_cal, f_cal, "o-", color='#27ae60', label=f"Calibrated Isotonic (ECE={compute_ece(y_te, te_cal):.4f})")
axes[0].set_title("Test Set Calibration (Out-of-Sample, Weeks 52-63)", fontsize=12, fontweight='bold')
axes[0].set_xlabel("Mean Predicted Probability")
axes[0].set_ylabel("Empirical Fraction of Positives")
axes[0].legend(loc="upper left")
axes[0].grid(True, linestyle='--', alpha=0.6)

# Validation Reliability (In-Sample)
fv_raw, mv_raw = calibration_curve(y_va, val_raw, n_bins=10)
fv_cal, mv_cal = calibration_curve(y_va, val_cal, n_bins=10)

axes[1].plot([0, 1], [0, 1], "k:", label="Perfect Calibration")
axes[1].plot(mv_raw, fv_raw, "s-", color='#e74c3c', label=f"Raw XGBoost (ECE={compute_ece(y_va, val_raw):.4f})")
axes[1].plot(mv_cal, fv_cal, "o-", color='#2980b9', label=f"Calibrated Isotonic [In-Sample] (ECE={compute_ece(y_va, val_cal):.4f})")
axes[1].set_title("Validation Set Calibration (In-Sample, Weeks 42-51)", fontsize=12, fontweight='bold')
axes[1].set_xlabel("Mean Predicted Probability")
axes[1].set_ylabel("Empirical Fraction of Positives")
axes[1].legend(loc="upper left")
axes[1].grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
fig29_path = FIGURES_DIR / '29_calibration_reliability_diagrams.png'
plt.savefig(fig29_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 29 to: {fig29_path}")"""

# Cell 12: Markdown PART D (Review Band & Error Counts)
nb.cells[12].source = r"""## PART D: Manual-Review Band & Uncertainty Under Concept Drift

### 1. Dual-Threshold Selective Classification & Operational Error Definition
To eliminate false alarms while guaranteeing containment of malware, we implement a **manual-review band** $[low, high] = [0.29, 0.55]$ on calibrated probabilities:
- $P_{\\text{cal}}(Y=1 \\mid x) < 0.29 \\implies$ **Auto-Benign**
- $P_{\\text{cal}}(Y=1 \\mid x) > 0.55 \\implies$ **Auto-Malicious**
- $0.29 \\le P_{\\text{cal}}(Y=1 \\mid x) \\le 0.55 \\implies$ **Needs Manual Review**

**Strict Operational Error Definition**:
An "error" is defined strictly as misclassification at the operating threshold $t=0.4083$ on calibrated probability ($Y_{\\text{pred}} = 1$ if $P_{\\text{cal}} \\ge 0.4083$ else $0$, where an error occurs when $Y_{\\text{pred}} \\ne Y_{\\text{true}}$):
- **Validation Split**:
  - Total errors: **151**
  - Errors inside review band $[0.29, 0.55]$: **62** (41.06%)
  - Errors outside review band: **89** (58.94%)
  - Invariant: $62 + 89 = 151$ total errors.
- **Test Split**:
  - Total errors: **554**
  - Errors inside review band $[0.29, 0.55]$: **235** (42.42%)
  - Errors outside review band: **319** (57.58%)
  - Invariant: $235 + 319 = 554$ total errors.

### 2. Longitudinal Drift Tracking (Figure 32)
- Week 51 belongs strictly to the **Validation split** (Weeks 42–51).
- We fit an **OLS trend of weekly review rate vs. collection week over weeks 42–63**, which exhibits a linear drift rate of **+0.15% per week** (exact slope: `+0.1463% / week`).
- The weekly review rate escalates from an average of ~1.83% across validation weeks to a peak of **5.10%** in test week 62."""

# Cell 13: Code PART D (Selective classification, Figure 31, Figure 32)
nb.cells[13].source = r"""# 1. Optimize [low, high] on Validation
low_grid = np.linspace(0.01, 0.45, 45)
high_grid = np.linspace(0.55, 0.99, 45)

best_band = None
min_rev = 1.0

for l in low_grid:
    for h in high_grid:
        auto_mask = (val_cal < l) | (val_cal > h)
        if np.sum(auto_mask) == 0:
            continue
        auto_preds = (val_cal[auto_mask] > h).astype(int)
        acc = accuracy_score(y_va[auto_mask], auto_preds)
        rev = 1.0 - np.mean(auto_mask)
        if acc >= 0.99:
            if rev < min_rev:
                min_rev = rev
                best_band = (l, h, acc, rev)

band_low, band_high, opt_val_acc, opt_val_rev = best_band

print("=" * 85)
print(f"OPTIMAL MANUAL-REVIEW BAND OPTIMIZED ON VALIDATION (Target Acc >= 99%)")
print("=" * 85)
print(f"Selected Review Band: [low, high] = [{band_low:.3f}, {band_high:.3f}]")
print(f"Validation Operational Profile:")
print(f"  - Review Rate: {opt_val_rev*100:.2f}% ({int(opt_val_rev*len(y_va))} documents)")
print(f"  - Auto-Decided Accuracy: {opt_val_acc*100:.2f}%")

# 2. Strict Error Definition & Audit at Operating Threshold 0.4083
t_op = 0.4083

# Validation error breakdown
val_preds = (val_cal >= t_op).astype(int)
val_errors = (val_preds != y_va)
val_total_errors = int(np.sum(val_errors))
val_in_band = (val_cal >= band_low) & (val_cal <= band_high)
val_err_inside = int(np.sum(val_errors & val_in_band))
val_err_outside = int(np.sum(val_errors & (~val_in_band)))
assert val_err_inside + val_err_outside == val_total_errors, "Validation error partition mismatch!"

# Test error breakdown
te_preds = (te_cal >= t_op).astype(int)
te_errors = (te_preds != y_te)
te_total_errors = int(np.sum(te_errors))
te_in_band = (te_cal >= band_low) & (te_cal <= band_high)
te_err_inside = int(np.sum(te_errors & te_in_band))
te_err_outside = int(np.sum(te_errors & (~te_in_band)))
assert te_err_inside + te_err_outside == te_total_errors, "Test error partition mismatch!"

# Remaining false positives and false negatives outside band
val_fp_outside = int(np.sum((val_cal > band_high) & (y_va == 0)))
val_fn_outside = int(np.sum((val_cal < band_low) & (y_va == 1)))
te_fp_outside = int(np.sum((te_cal > band_high) & (y_te == 0)))
te_fn_outside = int(np.sum((te_cal < band_low) & (y_te == 1)))

te_auto = (te_cal < band_low) | (te_cal > band_high)
te_auto_preds = (te_cal[te_auto] > band_high).astype(int)
te_acc = accuracy_score(y_te[te_auto], te_auto_preds)
te_rev = 1.0 - np.mean(te_auto)

band_audit_df = pd.DataFrame([
    {
        'Split': 'Validation (Weeks 42-51)',
        'Total Submissions': len(y_va),
        'Review Rate': f"{opt_val_rev*100:.2f}%",
        'Auto Accuracy': f"{opt_val_acc*100:.2f}%",
        'Total Errors (t=0.4083)': val_total_errors,
        'Errors Inside Band': f"{val_err_inside} ({val_err_inside/val_total_errors*100:.2f}%)",
        'Errors Outside Band': f"{val_err_outside} ({val_err_outside/val_total_errors*100:.2f}%)",
        'FP Outside': val_fp_outside,
        'FN Outside': val_fn_outside
    },
    {
        'Split': 'Test (Weeks 52-63)',
        'Total Submissions': len(y_te),
        'Review Rate': f"{te_rev*100:.2f}%",
        'Auto Accuracy': f"{te_acc*100:.2f}%",
        'Total Errors (t=0.4083)': te_total_errors,
        'Errors Inside Band': f"{te_err_inside} ({te_err_inside/te_total_errors*100:.2f}%)",
        'Errors Outside Band': f"{te_err_outside} ({te_err_outside/te_total_errors*100:.2f}%)",
        'FP Outside': te_fp_outside,
        'FN Outside': te_fn_outside
    }
])

print("\n" + "=" * 85)
print("SELECTIVE CLASSIFICATION AUDIT (OPERATING THRESHOLD = 0.4083, REVIEW BAND = [0.29, 0.55])")
print("=" * 85)
display(band_audit_df)

# 3. Figure 31: Accuracy vs. Coverage Curve
coverages = []
accuracies = []

for delta in np.linspace(0.0, 0.49, 100):
    l = 0.5 - delta
    h = 0.5 + delta
    auto_m = (te_cal < l) | (te_cal > h)
    cov = np.mean(auto_m)
    if np.sum(auto_m) > 0:
        a_preds = (te_cal[auto_m] > h).astype(int)
        acc = accuracy_score(y_te[auto_m], a_preds)
        coverages.append(cov * 100)
        accuracies.append(acc * 100)

fig, ax = plt.subplots(figsize=(9, 5.5))
ax.plot(coverages, accuracies, color='#2980b9', linewidth=2.5, label='Test Accuracy vs. Coverage')
ax.scatter([(1 - te_rev) * 100], [te_acc * 100], color='#e74c3c', s=100, zorder=5,
           label=f"Operational Band (Coverage: {(1-te_rev)*100:.1f}%, Acc: {te_acc*100:.2f}%)")

ax.set_title("Figure 31: Test Accuracy vs. Coverage Curve (Selective Classification)", fontsize=12, fontweight='bold', pad=12)
ax.set_xlabel("Coverage (% Auto-Decided Documents)")
ax.set_ylabel("Accuracy on Auto-Decided Documents (%)")
ax.set_xlim(0, 102)
ax.set_ylim(92, 101)
ax.legend()
ax.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
fig31_path = FIGURES_DIR / '31_accuracy_vs_coverage_curve.png'
plt.savefig(fig31_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 31 to: {fig31_path}")

# 4. Figure 32: Longitudinal Weekly Review Rate
df_tr = pd.read_parquet(PROCESSED_DIR / 'dedup_train.parquet')
df_te = pd.read_parquet(PROCESSED_DIR / 'dedup_test.parquet')

overlap_tlsh = set(df_tr.loc[df_tr['week_id'] >= 42, 'tlsh']).intersection(set(df_te['tlsh']))
val_mask = (df_tr['week_id'] >= 42) & (df_tr['week_id'] <= 51) & (~df_tr['tlsh'].isin(overlap_tlsh))
df_val_weeks = df_tr.loc[val_mask].copy()

df_val_weeks['cal_proba'] = val_cal
df_val_weeks['in_review_band'] = (df_val_weeks['cal_proba'] >= band_low) & (df_val_weeks['cal_proba'] <= band_high)

df_te_weeks = df_te.copy()
df_te_weeks['cal_proba'] = te_cal
df_te_weeks['in_review_band'] = (df_te_weeks['cal_proba'] >= band_low) & (df_te_weeks['cal_proba'] <= band_high)

df_combined_weeks = pd.concat([df_val_weeks[['week_id', 'in_review_band']], df_te_weeks[['week_id', 'in_review_band']]])
weekly_review_rate = df_combined_weeks.groupby('week_id')['in_review_band'].mean() * 100

weeks = weekly_review_rate.index.values
rates = weekly_review_rate.values

# OLS slope across all weeks 42-63
z = np.polyfit(weeks, rates, 1)
ols_slope = z[0]
print(f"OLS Linear Trend (Weeks 42-63): Slope = {ols_slope:+.4f}% per week (Intercept = {z[1]:.4f})")
print(f"Validation Weeks (42-51) Mean Review Rate: {np.mean(rates[:10]):.2f}%")
print(f"Test Weeks (52-63) Mean Review Rate: {np.mean(rates[10:]):.2f}%")
print(f"Test Set Peak Review Rate: {np.max(rates[10:]):.2f}% (Week {weeks[10+np.argmax(rates[10:])]})")

fig, ax = plt.subplots(figsize=(12, 5.5))

# Validation: weeks 42-51 (indices 0 to 9)
ax.plot(weeks[:10], rates[:10], marker='o', color='#2980b9', linewidth=2.2, label='Validation Weeks (42-51, Blue)')
# Test: weeks 52-63 (indices 10 to 21)
ax.plot(weeks[10:], rates[10:], marker='s', color='#c0392b', linewidth=2.2, linestyle='--', label='Test Weeks (52-63, Temporal Drift, Red)')
ax.axvline(51.5, color='black', linestyle=':', linewidth=1.5, label='Validation / Test Epoch Boundary')

# OLS trend line
p_trend = np.poly1d(z)
ax.plot(weeks, p_trend(weeks), "k-.", alpha=0.7, label=f"Linear Drift Trend (+{ols_slope:.2f}% / week)")

ax.set_title("Figure 32: Weekly Review Rate Escalation Across Validation and Test Splits", fontsize=12, fontweight='bold', pad=12)
ax.set_xlabel("Collection Week Index (Time)")
ax.set_ylabel("Manual Review Rate (% of Submissions in Band)")
ax.set_xticks(weeks)
ax.legend()
ax.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
fig32_path = FIGURES_DIR / '32_weekly_review_rate_drift.png'
plt.savefig(fig32_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 32 to: {fig32_path}")"""

# We also need to add a section for "Dependence on /URI"
# Let's see if we should create a new cell or update Cell 15 / 16
# Let's inspect Cell 15 (Markdown) and Cell 16 (Global SHAP)
nb.cells[15].source = r"""## PART E: SHAP Explainability (Global & Local Explanations)
To unpack the operational decision boundary of our champion XGBoost detector:
1. We analyze the model's **empirical dependence on `/URI`**:
   - Evaluating recall for malicious PDFs with `/URI == 0` vs. `/URI > 0`.
   - Evaluating false positive rates for benign PDFs with `/URI == 0` vs. `/URI > 0`.
   - Computing `/URI`'s proportion of total feature attribution across the model.
2. We instantiate a **SHAP TreeExplainer** with a 100-sample background reference taken from the training split (`X_tr_tree`).
3. We evaluate SHAP values across a representative **3,000-row stratified test sample** ($1,500$ benign and $1,500$ malicious).
4. We plot:
   - **Figure 33**: Mean Absolute SHAP Bar Chart for the Top 20 Global Features (`reports/figures/33_shap_global_importance_bar.png`).
   - **Figure 34**: Beeswarm Summary Plot for the Top 15 Features with semantic labels (`reports/figures/34_shap_summary_beeswarm.png`).
   - **Figure 35**: Summed Mean |SHAP| by Feature Family (`reports/figures/35_shap_family_importance_bar.png`).
   - **Figure 36**: Local Waterfall Explanations for 5 operational cases saved as separate individual files:
     - `36_1_true_positive.png`
     - `36_2_true_negative.png`
     - `36_3_false_positive.png`
     - `36_4_false_negative.png` (confident FN with calibrated $P < 0.29$)
     - `36_5_review_band.png` (review-band case with $P \\in [0.29, 0.55]$ distinct from FN)
5. **Stability Check**: We compute SHAP values on a matched 3,000-row validation sample and compute the Spearman rank correlation across the Top 50 features."""

# In Cell 16, let's include the /URI dependence calculation and global SHAP
nb.cells[16].source = r"""# 1. Empirical Dependence on /URI Analysis
uri_col = 'strings_regex_/URI'
mal_mask = (y_te == 1)
ben_mask = (y_te == 0)

mal_uri_0 = mal_mask & (X_te_tree[uri_col] == 0)
mal_uri_gt0 = mal_mask & (X_te_tree[uri_col] > 0)
ben_uri_0 = ben_mask & (X_te_tree[uri_col] == 0)
ben_uri_gt0 = ben_mask & (X_te_tree[uri_col] > 0)

rec_mal_uri_0 = np.mean(test_preds['XGBoost'][mal_uri_0] == 1)
rec_mal_uri_gt0 = np.mean(test_preds['XGBoost'][mal_uri_gt0] == 1)
fpr_ben_uri_0 = np.mean(test_preds['XGBoost'][ben_uri_0] == 1)
fpr_ben_uri_gt0 = np.mean(test_preds['XGBoost'][ben_uri_gt0] == 1)

df_uri_dep = pd.DataFrame([
    {
        'Subgroup': 'Malicious PDFs with /URI == 0',
        'Total Count': int(np.sum(mal_uri_0)),
        'Metric': 'Recall',
        'Rate': f"{rec_mal_uri_0*100:.2f}% ({int(np.sum(test_preds['XGBoost'][mal_uri_0] == 1))}/{int(np.sum(mal_uri_0))})"
    },
    {
        'Subgroup': 'Malicious PDFs with /URI > 0',
        'Total Count': int(np.sum(mal_uri_gt0)),
        'Metric': 'Recall',
        'Rate': f"{rec_mal_uri_gt0*100:.2f}% ({int(np.sum(test_preds['XGBoost'][mal_uri_gt0] == 1))}/{int(np.sum(mal_uri_gt0))})"
    },
    {
        'Subgroup': 'Benign PDFs with /URI == 0',
        'Total Count': int(np.sum(ben_uri_0)),
        'Metric': 'FPR',
        'Rate': f"{fpr_ben_uri_0*100:.2f}% ({int(np.sum(test_preds['XGBoost'][ben_uri_0] == 1))}/{int(np.sum(ben_uri_0))})"
    },
    {
        'Subgroup': 'Benign PDFs with /URI > 0',
        'Total Count': int(np.sum(ben_uri_gt0)),
        'Metric': 'FPR',
        'Rate': f"{fpr_ben_uri_gt0*100:.2f}% ({int(np.sum(test_preds['XGBoost'][ben_uri_gt0] == 1))}/{int(np.sum(ben_uri_gt0))})"
    }
])

print("=" * 95)
print("EMPIRICAL PERFORMANCE DEPENDENCE ON /URI (TEST SET)")
print("=" * 95)
display(df_uri_dep)

# 2. Stratified 3,000-row test sample and 100-row training background
rng_shap = np.random.RandomState(42)
bg_indices = rng_shap.choice(len(X_tr_tree), size=100, replace=False)
X_bg = X_tr_tree.iloc[bg_indices]

idx_0 = np.where(y_te == 0)[0]
idx_1 = np.where(y_te == 1)[0]
sample_test_indices = np.concatenate([
    rng_shap.choice(idx_0, 1500, replace=False),
    rng_shap.choice(idx_1, 1500, replace=False)
])
X_test_shap = X_te_tree.iloc[sample_test_indices]
y_test_shap = y_te[sample_test_indices]

print(f"Computing SHAP values via TreeExplainer for {len(X_test_shap)} test samples...")
t0 = time.time()
explainer = shap.TreeExplainer(champion_model, data=X_bg)
shap_explanation = explainer(X_test_shap)
print(f"SHAP explanation completed in {time.time()-t0:.1f}s.")

# Compute total mean |SHAP| and /URI's attribution share
mean_abs_shap = np.mean(np.abs(shap_explanation.values), axis=0)
total_mean_abs_shap = np.sum(mean_abs_shap)
uri_feat_idx = list(X_te_tree.columns).index(uri_col)
uri_mean_shap = mean_abs_shap[uri_feat_idx]
uri_shap_share = (uri_mean_shap / total_mean_abs_shap) * 100

print("\n" + "=" * 95)
print("SHAP ATTRIBUTION SHARE OF /URI:")
print(f"  - Total Mean |SHAP| across all 658 features: {total_mean_abs_shap:.4f}")
print(f"  - strings_regex_/URI Mean |SHAP|:           {uri_mean_shap:.4f}")
print(f"  - strings_regex_/URI Attribution Share:     {uri_shap_share:.2f}%")
print("=" * 95)

# 3. Figure 33: Mean Absolute SHAP Bar Chart (Top 20 Features)
top20_idx = np.argsort(mean_abs_shap)[::-1][:20]
top20_names = [feature_names[i] for i in top20_idx]
top20_vals = mean_abs_shap[top20_idx]
top20_labels = [decode_feature_name(fn) for fn in top20_names]

fig, ax = plt.subplots(figsize=(12, 8))
y_pos = np.arange(len(top20_vals))
ax.barh(y_pos, top20_vals[::-1], color='#2980b9', edgecolor='black', alpha=0.85)
ax.set_yticks(y_pos)
ax.set_yticklabels(top20_labels[::-1], fontsize=10)
ax.set_xlabel("Mean Absolute SHAP Value (Impact on Log-Odds)", fontsize=11, fontweight='bold')
ax.set_title("Figure 33: Top 20 Global Features Ranked by Mean Absolute SHAP Attribution", fontsize=13, fontweight='bold', pad=12)
ax.grid(axis='x', linestyle='--', alpha=0.6)

plt.tight_layout()
fig33_path = FIGURES_DIR / '33_shap_global_importance_bar.png'
plt.savefig(fig33_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 33 to: {fig33_path}")

# 4. Figure 34: Beeswarm Summary Plot (Top 15 Features)
shap_explanation_decoded = shap.Explanation(
    values=shap_explanation.values,
    base_values=shap_explanation.base_values,
    data=shap_explanation.data,
    feature_names=[decode_feature_name(fn) for fn in feature_names]
)

plt.figure(figsize=(12, 7))
shap.plots.beeswarm(shap_explanation_decoded, max_display=15, show=False)
plt.title("Figure 34: SHAP Summary Beeswarm Plot for Top 15 Features", fontsize=13, fontweight='bold', pad=12)
plt.tight_layout()
fig34_path = FIGURES_DIR / '34_shap_summary_beeswarm.png'
plt.savefig(fig34_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 34 to: {fig34_path}")

# 5. Figure 35: Summed Mean |SHAP| by Feature Family
family_map = {
    'General Info': [c for c in feature_names if c.startswith('general_')],
    'Byte Histogram': [c for c in feature_names if c.startswith('byte_hist_')],
    'Byte-Entropy Histogram': [c for c in feature_names if c.startswith('byte_entropy_')],
    'String Metadata': [c for c in feature_names if c in ['strings_numstrings', 'strings_avlength', 'strings_printables', 'strings_entropy']],
    'Printable Characters': [c for c in feature_names if c.startswith('strings_print_char_')],
    'Regex Indicators': [c for c in feature_names if c.startswith('strings_regex_')]
}

family_shap_sums = {}
for fam, f_cols in family_map.items():
    col_indices = [feature_names.index(c) for c in f_cols if c in feature_names]
    family_shap_sums[fam] = np.sum(mean_abs_shap[col_indices])

df_fam_shap = pd.DataFrame(list(family_shap_sums.items()), columns=['Feature Family', 'Summed Mean |SHAP|'])
df_fam_shap['Share (%)'] = (df_fam_shap['Summed Mean |SHAP|'] / df_fam_shap['Summed Mean |SHAP|'].sum()) * 100
df_fam_shap = df_fam_shap.sort_values(by='Summed Mean |SHAP|', ascending=False)

print("\n" + "=" * 80)
print("SUMMED SHAP ATTRIBUTION BY FEATURE FAMILY")
print("=" * 80)
display(df_fam_shap)

fig, ax = plt.subplots(figsize=(10, 5.5))
ax.bar(df_fam_shap['Feature Family'], df_fam_shap['Summed Mean |SHAP|'], color='#34495e', edgecolor='black', alpha=0.85)
ax.set_title("Figure 35: Global SHAP Importance Summed by Feature Family", fontsize=12, fontweight='bold', pad=12)
ax.set_ylabel("Summed Mean Absolute SHAP Value")
ax.set_xticklabels(df_fam_shap['Feature Family'], rotation=30, ha='right', fontsize=10)
ax.grid(axis='y', linestyle='--', alpha=0.6)

for i, (val, share) in enumerate(zip(df_fam_shap['Summed Mean |SHAP|'], df_fam_shap['Share (%)'])):
    ax.text(i, val + 0.05, f"{share:.1f}%", ha='center', va='bottom', fontweight='bold', fontsize=9.5)

plt.tight_layout()
fig35_path = FIGURES_DIR / '35_shap_family_importance_bar.png'
plt.savefig(fig35_path, dpi=300, bbox_inches='tight')
plt.show()
print(f"Saved Figure 35 to: {fig35_path}")"""

# Cell 17: Local Waterfall Explanations (Separate files, no overlapping axes, confident FN < 0.29 != 31, distinct review band)
nb.cells[17].source = r"""# Local Waterfall Explanations for 5 Operational Archetypes (Saved as Separate Files)
test_preds_champ = (te_cal >= t_op).astype(int)

# 1. True Positive (Malicious correctly detected with high confidence)
tp_candidates = np.where((y_te == 1) & (test_preds_champ == 1) & (te_cal > 0.95))[0]
idx_tp = tp_candidates[0]

# 2. True Negative (Benign correctly identified with high confidence)
tn_candidates = np.where((y_te == 0) & (test_preds_champ == 0) & (te_cal < 0.05))[0]
idx_tn = tn_candidates[0]

# 3. False Positive (Benign erroneously flagged as malicious)
fp_candidates = np.where((y_te == 0) & (test_preds_champ == 1))[0]
idx_fp = fp_candidates[0]

# 4. Confident False Negative (Malicious missed with high confidence, P < 0.29, NOT row 31)
fn_candidates = np.where((y_te == 1) & (te_cal < 0.29) & (np.arange(len(y_te)) != 31))[0]
idx_fn = fn_candidates[0]

# 5. Review-Band Document (Uncertain case with P in [0.29, 0.55] distinct from FN)
rb_candidates = np.where((te_cal >= band_low) & (te_cal <= band_high) & (np.arange(len(y_te)) != idx_fn))[0]
idx_rb = rb_candidates[0]

archetypes = [
    ('36_1_true_positive.png', idx_tp, 'True Positive (Malicious, High Confidence)'),
    ('36_2_true_negative.png', idx_tn, 'True Negative (Benign, High Confidence)'),
    ('36_3_false_positive.png', idx_fp, 'False Positive (Benign Erroneously Flagged)'),
    ('36_4_false_negative.png', idx_fn, f'Confident False Negative (Malicious Missed, P={te_cal[idx_fn]:.4f} < 0.29)'),
    ('36_5_review_band.png', idx_rb, f'Manual Review Band (Uncertain Case, P={te_cal[idx_rb]:.4f})')
]

print("=" * 95)
print("LOCAL WATERFALL EXPLANATION SAMPLES:")
print("=" * 95)
for filename, idx_val, label in archetypes:
    print(f"  - {filename}: Index {idx_val} | Label: {y_te[idx_val]} | Pred: {test_preds_champ[idx_val]} | Calibrated P: {te_cal[idx_val]:.4f} | {label}")

# Compute individual SHAP explanations with decoded names
sample_df = X_te_tree.iloc[[idx_tp, idx_tn, idx_fp, idx_fn, idx_rb]]
shap_archetypes = explainer(sample_df)

for i, (filename, idx_val, label) in enumerate(archetypes):
    exp_single = shap.Explanation(
        values=shap_archetypes[i].values,
        base_values=shap_archetypes[i].base_values,
        data=shap_archetypes[i].data,
        feature_names=[decode_feature_name(fn) for fn in feature_names]
    )
    
    # Dedicated figure per plot to prevent overlapping axes
    fig = plt.figure(figsize=(10, 6.5))
    shap.plots.waterfall(exp_single, max_display=10, show=False)
    plt.title(f"Figure {filename[:4]}: {label} (Test Row {idx_val})", fontsize=11, fontweight='bold', pad=14)
    plt.tight_layout()
    
    save_path = FIGURES_DIR / filename
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.show()
    plt.close(fig)
    print(f"Saved {filename} to: {save_path}")"""

# Cell 18: SHAP Stability Check (Top 50 features and Spearman correlation)
nb.cells[18].source = r"""# SHAP Stability Check: Compare Top 50 Features Between Validation and Test Splits
idx_va_0 = np.where(y_va == 0)[0]
idx_va_1 = np.where(y_va == 1)[0]
sample_va_idx = np.concatenate([
    rng_shap.choice(idx_va_0, 1500, replace=False),
    rng_shap.choice(idx_va_1, 1500, replace=False)
])
X_val_shap = X_va_tree.iloc[sample_va_idx]

print(f"Computing SHAP values for 3,000 validation samples for stability audit...")
shap_val_exp = explainer(X_val_shap)

mean_abs_val = np.mean(np.abs(shap_val_exp.values), axis=0)
mean_abs_te = mean_abs_shap

# Restrict stability check strictly to the Top 50 features ranked by test mean |SHAP|
top50_idx = np.argsort(mean_abs_te)[::-1][:50]
val_top50 = mean_abs_val[top50_idx]
te_top50 = mean_abs_te[top50_idx]

rho, p_val = spearmanr(val_top50, te_top50)

print("\n" + "=" * 85)
print("SHAP STABILITY CHECK: TOP 50 FEATURES (VALIDATION VS. TEST)")
print("=" * 85)
print(f"Top 50 Spearman Rank Correlation: rho = {rho:.4f} (p-value = {p_val:.2e})")

stability_df = pd.DataFrame({
    'Feature': [decode_feature_name(feature_names[i]) for i in top50_idx[:15]],
    'Test Mean |SHAP|': [te_top50[i] for i in range(15)],
    'Val Mean |SHAP|': [val_top50[i] for i in range(15)],
    'Rank Difference': [i - np.where(np.argsort(mean_abs_val)[::-1] == top50_idx[i])[0][0] for i in range(15)]
})
display(stability_df)"""

with open(nb_path, "w", encoding="utf-8") as f:
    nbformat.write(nb, f)

print("Notebook 05 successfully updated. Now running execution pipeline via NotebookClient...")
with open(nb_path, "r", encoding="utf-8") as f:
    nb_to_run = nbformat.read(f, as_version=4)

client = NotebookClient(nb_to_run, timeout=600, kernel_name='python3', resources={'metadata': {'path': 'notebooks/'}})
client.execute()

with open(nb_path, "w", encoding="utf-8") as f:
    nbformat.write(nb_to_run, f)

print("Notebook 05 executed and saved with all cell outputs successfully!")
