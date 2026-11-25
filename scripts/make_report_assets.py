"""
DocSentry Report Assets Bundler
==============================
Copies final figures (20-39 and ui_*.png) and reports/*.csv into `report_assets/`
and generates `report_assets/index.md` listing each file, a one-line caption,
and the source notebook or script that generated it.
"""

import re
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
FIGURES_DIR = BASE_DIR / "reports" / "figures"
REPORTS_DIR = BASE_DIR / "reports"
OUT_DIR = BASE_DIR / "report_assets"

# Known figure metadata: prefix/name -> (caption, source)
FIGURE_META = {
    "20_": ("Validation F1, Recall, and ROC-AUC comparison across tuned classifiers.", "notebooks/04_modeling.ipynb"),
    "21_": ("Test-set confusion matrices for all four evaluated classifiers (N=12,000).", "notebooks/04_modeling.ipynb"),
    "22_": ("Test-set ROC curves comparing discriminative performance across models.", "notebooks/04_modeling.ipynb"),
    "23_": ("Test-set Precision-Recall curves across models.", "notebooks/04_modeling.ipynb"),
    "24_": ("Top XGBoost gain feature importances (raw feature names).", "notebooks/04_modeling.ipynb"),
    "25_": ("Malicious training file size cluster distribution (25 KB to 500 KB modes).", "notebooks/04_modeling.ipynb"),
    "26_": ("Top XGBoost feature importances with decoded ASCII and byte-entropy labels.", "notebooks/04_modeling.ipynb"),
    "27_": ("Bootstrap 95% confidence intervals (1,000 resamples) for F1, Recall, FPR, and ROC-AUC.", "notebooks/05_explain_uncertainty.ipynb"),
    "28_": ("Full unmatched test set vs. 1:1 size-matched evaluation across 8 size bins.", "notebooks/05_explain_uncertainty.ipynb"),
    "29_": ("Probability calibration reliability diagrams on validation vs. unseen test splits.", "notebooks/05_explain_uncertainty.ipynb"),
    "30_": ("Operating threshold recall vs. false positive rate tradeoff curve.", "notebooks/05_explain_uncertainty.ipynb"),
    "31_": ("Selective classification accuracy vs. coverage curve across review-band widths.", "notebooks/05_explain_uncertainty.ipynb"),
    "32_": ("Weekly manual-review rate temporal drift across Weeks 42-63 with OLS trend.", "notebooks/05_explain_uncertainty.ipynb"),
    "33_": ("Global top-20 features ranked by mean absolute SHAP value (N=3,000).", "notebooks/05_explain_uncertainty.ipynb"),
    "34_": ("SHAP summary beeswarm plot for the top 15 features.", "notebooks/05_explain_uncertainty.ipynb"),
    "35_": ("Global SHAP importance summed across the 6 static feature families.", "notebooks/05_explain_uncertainty.ipynb"),
    "36_1_": ("Local SHAP waterfall explanation for a high-confidence True Positive sample.", "notebooks/05_explain_uncertainty.ipynb"),
    "36_2_": ("Local SHAP waterfall explanation for a high-confidence True Negative sample.", "notebooks/05_explain_uncertainty.ipynb"),
    "36_3_": ("Local SHAP waterfall explanation for a False Positive sample.", "notebooks/05_explain_uncertainty.ipynb"),
    "36_4_": ("Local SHAP waterfall explanation for a confident False Negative sample (P < 0.29).", "notebooks/05_explain_uncertainty.ipynb"),
    "36_5_": ("Local SHAP waterfall explanation for a Manual Review Band sample (P in [0.29, 0.55]).", "notebooks/05_explain_uncertainty.ipynb"),
    "36_shap": ("Combined local SHAP waterfall explanations summary.", "notebooks/05_explain_uncertainty.ipynb"),
    "37_": ("Local SHAP feature contributions across the 6 synthetic demo PDFs.", "notebooks/06_real_pdf_demo.ipynb"),
    "38_": ("Isotonic regression calibration step function showing the [0.2004, 0.3034] -> 0.4082 plateau.", "notebooks/07_demo_diagnostics.ipynb"),
    "39_": ("Training distribution of file size and string count with 0.5%-99.5% OOD bounds.", "notebooks/07_demo_diagnostics.ipynb"),
}

CSV_META = {
    "model_comparison.csv": ("Validation and test benchmark metrics across Logistic Regression, Random Forest, XGBoost, and HistGradientBoosting.", "notebooks/04_modeling.ipynb"),
    "demo_scan_results.csv": ("Batch static scan results, probabilities, OOD flags, and top 3 SHAP contributors for demo PDFs.", "scripts/scan_pdfs.py"),
}


def get_figure_info(filename: str):
    if filename.startswith("ui_"):
        return (f"Headless browser UI screenshot ({filename.removesuffix('.png').replace('_', ' ')}).", "scripts/capture_ui_screenshots.py")
    for prefix, info in FIGURE_META.items():
        if filename.startswith(prefix):
            return info
    return ("Project evaluation figure.", "notebooks/")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig_out = OUT_DIR / "figures"
    fig_out.mkdir(parents=True, exist_ok=True)

    copied_figs = []
    fig_pattern = re.compile(r"^(2[0-9]|3[0-9])_.*\.png$|^ui_.*\.png$")
    for p in sorted(FIGURES_DIR.glob("*.png")):
        if fig_pattern.match(p.name):
            shutil.copy2(p, fig_out / p.name)
            copied_figs.append(p.name)

    copied_csvs = []
    for p in sorted(REPORTS_DIR.glob("*.csv")):
        shutil.copy2(p, OUT_DIR / p.name)
        copied_csvs.append(p.name)

    # Build index.md
    lines = [
        "# DocSentry Report Assets Index",
        "",
        "## Figures (`figures/`)",
        "",
        "| File | Caption | Source |",
        "| :--- | :--- | :--- |",
    ]
    for name in copied_figs:
        caption, source = get_figure_info(name)
        lines.append(f"| `figures/{name}` | {caption} | `{source}` |")

    lines.extend([
        "",
        "## Tabular Reports",
        "",
        "| File | Caption | Source |",
        "| :--- | :--- | :--- |",
    ])
    for name in copied_csvs:
        caption, source = CSV_META.get(name, ("Generated CSV report.", "scripts/"))
        lines.append(f"| `{name}` | {caption} | `{source}` |")

    index_path = OUT_DIR / "index.md"
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Copied {len(copied_figs)} figures and {len(copied_csvs)} CSVs to {OUT_DIR}")
    print(f"Generated index: {index_path}")


if __name__ == "__main__":
    main()
