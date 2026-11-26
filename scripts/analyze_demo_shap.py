"""Extract top-5 SHAP contributors for the 6 synthetic PDFs and user_pdf_3 / user_pdf_8."""
from pathlib import Path
import sys
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.docsentry_extract import scan
from app.main import get_readable_feature_name


def main() -> None:
    synth_dir = ROOT / "data" / "demo_pdfs" / "synthetic"
    user_dir = ROOT / "data" / "demo_pdfs" / "user"

    synth_files = sorted(synth_dir.glob("*.pdf"))
    user_files = sorted(user_dir.glob("*.pdf"))

    targets = [(p.name, p) for p in synth_files]
    if len(user_files) >= 8:
        targets.append(("user_pdf_3.pdf", user_files[2]))
        targets.append(("user_pdf_8.pdf", user_files[7]))

    for alias, path in targets:
        res = scan(path)
        print(
            f"FILE: {alias} | label={res['label']} | "
            f"cal={res['calibrated_probability']:.4f} | raw={res['raw_probability']:.4f}"
        )
        for i, c in enumerate(res["top_contributors"][:5], 1):
            rname = get_readable_feature_name(c["feature"])
            print(f"  {i}. {rname} | shap={c['shap_value']:+.4f} | dir={c['direction']} | raw_feat={c['feature']}")

    df = pd.read_csv(ROOT / "reports" / "domain_shift_demo.csv")
    plateau = df[df["calibrated_probability"].round(4) == 0.4082]["alias"].tolist()
    print(f"\nPLATEAU_0.4082 ({len(plateau)}/15): {plateau}")


if __name__ == "__main__":
    main()
