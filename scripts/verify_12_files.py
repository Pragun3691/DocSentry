import io
import sys
from pathlib import Path
import pandas as pd

BASE_DIR = Path.cwd()
sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from app.main import app

CSV_PATH = BASE_DIR / "reports/demo_scan_results.csv"
df_csv = pd.read_csv(CSV_PATH)

synthetic_targets = [
    ("synthetic_a_minimal_blank.pdf", "synthetic_a_minimal_blank.pdf"),
    ("synthetic_c_20_page_report.pdf", "synthetic_c_20_page_report.pdf"),
    ("synthetic_f_large_5mb.pdf", "synthetic_f_large_5mb.pdf"),
]

user_pdfs = sorted((BASE_DIR / "data/demo_pdfs/user").glob("*.pdf"))
user_targets = [(p.name, f"user_pdf_{i+1}.pdf") for i, p in enumerate(user_pdfs)]

all_targets = synthetic_targets + user_targets

mismatches = []
rows_12 = []

for disk_name, csv_name in all_targets:
    matches = list((BASE_DIR / "data/demo_pdfs").rglob(disk_name))
    assert len(matches) == 1, f"Found {len(matches)} matches for {disk_name}"
    file_path = matches[0]

    csv_row = df_csv[df_csv['file'] == csv_name].iloc[0]

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    with TestClient(app) as test_client:
        res = test_client.post(
            "/scan",
            files={"file": (csv_name, io.BytesIO(file_bytes), "application/pdf")}
        )
    assert res.status_code == 200, f"Scan failed for {csv_name}: {res.text}"
    api_data = res.json()

    csv_cal_p = round(float(csv_row['calibrated_probability']), 4)
    api_cal_p = round(float(api_data['calibrated_probability']), 4)
    csv_raw_p = round(float(csv_row['raw_probability']), 4)
    api_raw_p = round(float(api_data['raw_probability']), 4)
    csv_verdict = str(csv_row['verdict'])
    api_verdict = str(api_data['verdict'])
    csv_sha = str(csv_row['sha256'])
    api_sha = str(api_data['sha256'])
    csv_size = int(csv_row['size'])
    api_size = int(api_data['size'])
    csv_ood = bool(csv_row['ood_warning'])
    api_ood = bool(api_data['ood_warning'])

    if csv_cal_p != api_cal_p:
        mismatches.append(f"{csv_name}: cal_p mismatch")
    if csv_raw_p != api_raw_p:
        mismatches.append(f"{csv_name}: raw_p mismatch")
    if csv_verdict != api_verdict:
        mismatches.append(f"{csv_name}: verdict mismatch")
    if csv_sha != "redacted" and csv_sha != api_sha:
        mismatches.append(f"{csv_name}: sha256 mismatch")
    if csv_size != api_size:
        mismatches.append(f"{csv_name}: size mismatch")
    if csv_ood != api_ood:
        mismatches.append(f"{csv_name}: ood mismatch")

print(f"Total files compared: {len(all_targets)}")
print(f"Mismatches count: {len(mismatches)}")
assert len(mismatches) == 0, f"Mismatches found: {mismatches}"
print("ALL CSV AND API FIELDS MATCH PERFECTLY (0 MISMATCHES)!")
