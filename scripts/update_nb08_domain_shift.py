"""Update Notebook 08 Part B with f-string computed domain-shift summary and column note."""
import json
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
NB_PATH = ROOT / "notebooks" / "08_uri_counterfactual.ipynb"
CSV_PATH = ROOT / "reports" / "domain_shift_demo.csv"

CODE_CELL_SOURCE = """# Compute domain-shift summary statistics and column note from reports/domain_shift_demo.csv
df_domain = pd.read_csv(REPORTS_DIR / 'domain_shift_demo.csv')

synth_ae = df_domain[df_domain['alias'].str.startswith(('synthetic_a', 'synthetic_b', 'synthetic_c', 'synthetic_d', 'synthetic_e'))]
synth_f = df_domain[df_domain['alias'].str.startswith('synthetic_f')].iloc[0]
user_df = df_domain[df_domain['group'] == 'user_anonymised']

n_user = len(user_df)
n_user_lt25 = int((user_df['size_pct_rank'] < 25).sum())
u_sz_min, u_sz_max = user_df['size_pct_rank'].min(), user_df['size_pct_rank'].max()
u_st_min, u_st_max = user_df['numstrings_pct_rank'].min(), user_df['numstrings_pct_rank'].max()
u_en_min, u_en_max = user_df['entropy_pct_rank'].min(), user_df['entropy_pct_rank'].max()
u_lt25_min = user_df.loc[user_df['size_pct_rank'] < 25, 'size_pct_rank'].min()
u_lt25_max = user_df.loc[user_df['size_pct_rank'] < 25, 'size_pct_rank'].max()

ae_sz_min, ae_sz_max = synth_ae['size_pct_rank'].min(), synth_ae['size_pct_rank'].max()
ae_st_min, ae_st_max = synth_ae['numstrings_pct_rank'].min(), synth_ae['numstrings_pct_rank'].max()
ae_en_min, ae_en_max = synth_ae['entropy_pct_rank'].min(), synth_ae['entropy_pct_rank'].max()

f_sz = synth_f['size_pct_rank']
f_st = synth_f['numstrings_pct_rank']
f_en = synth_f['entropy_pct_rank']

zero_uri_pct = float(df_domain.loc[df_domain['alias'] == 'synthetic_a_minimal_blank.pdf', 'uri_pct_rank'].iloc[0])
plateau_files = df_domain.loc[df_domain['calibrated_probability'].round(4) == 0.4082, 'alias'].tolist()
n_plateau = len(plateau_files)
n_total = len(df_domain)
n_user_benign = int((user_df['verdict'] == 'benign').sum())
n_user_review = int((user_df['verdict'] == 'needs_review').sum())

domain_shift_para = (
    f"Compared against the training benign distribution, the five small synthetic PDFs (`synthetic_a`–`synthetic_e`) "
    f"fall in the low tail of file size ({ae_sz_min:.2f}th–{ae_sz_max:.2f}th percentile), string count "
    f"({ae_st_min:.2f}th–{ae_st_max:.2f}th percentile), and entropy ({ae_en_min:.2f}th–{ae_en_max:.2f}th percentile). "
    f"`synthetic_f_large_5mb.pdf` is not in the low size tail: its 5.5 MB padding places it at the {f_sz:.2f}th size "
    f"and {f_st:.2f}th string-count percentile, while its entropy remains in the low tail ({f_en:.2f}th percentile). "
    f"By contrast, the {n_user} anonymised user PDFs (`user_pdf_1.pdf`–`user_pdf_9.pdf`) are spread across the range "
    f"of the training benign files with none in the extreme tails: size spans {u_sz_min:.2f}th–{u_sz_max:.2f}th percentile "
    f"({n_user_lt25} of {n_user} are below the 25th percentile, from {u_lt25_min:.2f}th to {u_lt25_max:.2f}th), "
    f"string count spans {u_st_min:.2f}th–{u_st_max:.2f}th percentile, and entropy spans {u_en_min:.2f}th–{u_en_max:.2f}th percentile; "
    f"{n_user_benign} are classified `benign` and {n_user_review} (`user_pdf_3.pdf` and `user_pdf_8.pdf`) are routed to `needs_review`. "
    f"Across all {n_total} demo files, {n_plateau} ({', '.join(f'`{x}`' for x in plateau_files)}) sit on the isotonic calibrator's `0.4082` plateau, which is why they receive `needs_review`."
)

column_note = (
    f"**Column note (`uri_pct_rank`):** `uri_pct_rank = {zero_uri_pct:.2f}` is a tie plateau meaning **zero links** "
    f"(`{zero_uri_pct:.2f}%` of training benign files have `/URI = 0`), not the 83rd percentile of link-heavy files. "
    f"Any value above `{zero_uri_pct:.2f}` indicates at least one `/URI` link (`user_pdf_7.pdf` at `88.29`, `user_pdf_8.pdf` at `89.46`, "
    f"`user_pdf_3.pdf` at `92.46`, and `synthetic_d_25_uris.pdf` at `96.10`)."
)

print(domain_shift_para)
print()
print(column_note)
"""


def main() -> None:
    nb = json.loads(NB_PATH.read_text(encoding="utf-8"))
    cells = nb["cells"]

    # Execute the code cell logic in a local namespace to capture exact output
    ns = {"pd": pd, "REPORTS_DIR": ROOT / "reports"}
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(CODE_CELL_SOURCE, ns)
    out_text = buf.getvalue()

    new_code_cell = {
        "cell_type": "code",
        "execution_count": 17,
        "metadata": {},
        "outputs": [
            {
                "name": "stdout",
                "output_type": "stream",
                "text": [line + "\n" for line in out_text.splitlines()],
            }
        ],
        "source": [line + "\n" for line in CODE_CELL_SOURCE.splitlines()],
    }

    md_text = (
        "### Domain-Shift Interpretation\n\n"
        + ns["domain_shift_para"]
        + "\n\n"
        + ns["column_note"]
        + "\n"
    )
    new_md_cell = {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in md_text.splitlines()],
    }

    # Replace cell 17 (old markdown) or cells 17+ if already inserted
    if len(cells) == 18 and cells[17]["cell_type"] == "markdown":
        nb["cells"] = cells[:17] + [new_code_cell, new_md_cell]
    elif len(cells) == 19 and cells[17]["cell_type"] == "code" and cells[18]["cell_type"] == "markdown":
        nb["cells"] = cells[:17] + [new_code_cell, new_md_cell]
    else:
        raise RuntimeError(f"Unexpected notebook cell structure: len={len(cells)}")

    NB_PATH.write_text(json.dumps(nb, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Updated Notebook 08 successfully.")
    print("--- OUTPUT ---")
    print(out_text)


if __name__ == "__main__":
    main()
