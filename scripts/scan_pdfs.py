"""
DocSentry PDF Scanner CLI Utility
=================================
Scans a directory of PDF documents, performs static feature extraction, executes
calibrated inference with review-band routing, and computes top local SHAP contributors.
Results are saved to `reports/demo_scan_results.csv` and displayed in the terminal.

Usage:
------
python scripts/scan_pdfs.py [--dir DIRECTORY] [--out OUTPUT_CSV]
"""

import os
import sys
import argparse
from pathlib import Path

import pandas as pd

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import src.docsentry_extract as de
import src.docsentry_infer as di


def scan_directory(target_dir: Path, output_csv: Path):
    print("=" * 105)
    print(f"DOCSENTRY PDF BATCH SCANNER: Scanning directory: {target_dir}")
    print("=" * 105)

    if not target_dir.exists():
        print(f"Error: Directory {target_dir} does not exist.")
        sys.exit(1)

    pdf_files = sorted(list(target_dir.rglob("*.pdf"))) if target_dir.is_dir() else [target_dir]
    if not pdf_files:
        print(f"No PDF files found in {target_dir}.")
        return

    print(f"Discovered {len(pdf_files)} PDF documents to analyze.\n")

    results = []

    for pdf_path in pdf_files:
        try:
            report = de.scan(pdf_path)
            
            top_3 = report['top_contributors'][:3]
            top_3_desc = "; ".join([
                f"{tc['readable_name']} ({tc['shap_value']:+.3f})"
                for tc in top_3
            ])

            results.append({
                'file': pdf_path.name,
                'size': report['file_size'],
                'sha256': report['sha256'],
                'verdict': report['label'],
                'calibrated_probability': report['calibrated_probability'],
                'raw_probability': report['raw_probability'],
                'ood_warning': report.get('ood_warning', False),
                'top_3_contributors': top_3_desc
            })

            print(f"  [+] Scanned: {pdf_path.name:<32} | Verdict: {report['label'].upper():<12} | Cal P: {report['calibrated_probability']:.4f} | Raw P: {report['raw_probability']:.4f}")

        except Exception as e:
            print(f"  [-] Failed:  {pdf_path.name:<32} | Error: {e}")
            results.append({
                'file': pdf_path.name,
                'size': pdf_path.stat().st_size if pdf_path.exists() else 0,
                'sha256': '',
                'verdict': 'error',
                'calibrated_probability': float('nan'),
                'raw_probability': float('nan'),
                'ood_warning': False,
                'top_3_contributors': str(e)
            })

    # Save to CSV
    df_results = pd.DataFrame(results)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df_results.to_csv(output_csv, index=False)
    print("\n" + "=" * 105)
    print(f"SCAN RESULTS SAVED TO: {output_csv}")
    print("=" * 105)
    print(df_results[['file', 'size', 'verdict', 'calibrated_probability']].to_string(index=False))


def main():
    parser = argparse.ArgumentParser(description="DocSentry PDF Batch Security Scanner")
    parser.add_argument("--dir", type=str, default="data/demo_pdfs",
                        help="Target directory containing PDF files to scan")
    parser.add_argument("--out", type=str, default="reports/demo_scan_results.csv",
                        help="Output path for scan results CSV")

    args = parser.parse_args()
    scan_directory(Path(args.dir), Path(args.out))


if __name__ == "__main__":
    main()
