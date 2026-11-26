import io
import json
import contextlib
import nbformat
import pandas as pd
from pathlib import Path

nb_path = Path("notebooks/08_uri_counterfactual.ipynb")
nb = nbformat.read(nb_path, as_version=4)

new_src = '''# Re-build What this shows strictly from computed variables with direction asserts
cf_report = json.loads((REPORTS_DIR / 'uri_counterfactual.json').read_text(encoding='utf-8'))
cf0 = cf_report['counterfactuals'][0]
ab_ctrl, ab_nouri, ab_noreg = cf_report['ablations']

tmat_mal = cf0['transition_malicious']
n_mal_to_rev = int(tmat_mal['needs_review']['malicious'])
n_mal_to_ben = int(tmat_mal['benign']['malicious'])
n_mal_lost_verdict = n_mal_to_rev + n_mal_to_ben
assert n_mal_lost_verdict == cf0['gt_zero_mal_flipped_from_malicious'], 'Transition matrix mismatch!'

rec_before = cf0['recall_before'] * 100
rec_after = cf0['recall_after'] * 100
rec_ci = cf0['recall_delta_ci95']
rev_before = cf0['review_rate_before'] * 100
rev_after = cf0['review_rate_after'] * 100

f1_ctrl = ab_ctrl['test']['f1']
f1_nouri = ab_nouri['test']['f1']
f1_noreg = ab_noreg['test']['f1']

assert rec_after < rec_before, 'Expected recall fall!'
assert rev_after > rev_before, 'Expected review rate rise!'
assert f1_nouri >= f1_ctrl, 'Expected no F1 drop without /URI!'
assert f1_noreg < f1_ctrl, 'Expected F1 loss without all regex!'

s_a = (
    f"(a) Shipped model with links removed (/URI = 0 in the feature table): recall at t = 0.4083 falls "
    f"from {rec_before:.2f}% to {rec_after:.2f}% (paired 95% CI for change: [{rec_ci[0]*100:+.2f}%, {rec_ci[1]*100:+.2f}%]) "
    f"and the review rate rises from {rev_before:.2f}% to {rev_after:.2f}%. Among link-bearing malicious files, "
    f"{n_mal_lost_verdict} lose the malicious verdict: {n_mal_to_rev} move to needs_review and {n_mal_to_ben} move to benign."
)
s_b = (
    "(b) Definition distinction: 'recall at t = 0.4083' counts files with calibrated probability >= 0.4083, "
    "whereas a 'malicious verdict' requires calibrated probability > 0.550 (above the review band). These are different "
    f"quantities, so the {n_mal_lost_verdict} malicious-verdict losses and the {rec_before - rec_after:.2f}-point recall fall at 0.4083 are not the same quantity."
)
s_c = (
    f"(c) Retraining without /URI (657 features): test F1 is {f1_nouri:.4f} (95% CI {ab_nouri['test_ci95']['f1']}) "
    f"vs {f1_ctrl:.4f} (95% CI {ab_ctrl['test_ci95']['f1']}) for the 658-feature control—the intervals overlap, so there is "
    f"no loss in test F1 (validation F1 is {ab_nouri['val']['f1']:.4f} vs {ab_ctrl['val']['f1']:.4f}). This indicates link "
    "information is partly redundant with other features in this dataset (an untested hypothesis is that byte or character "
    "frequencies of '/', 'U', 'R', 'I' or URL schemes act as proxies)."
)
s_d = (
    f"(d) Retraining without all 77 regex features (581 features): test F1 is {f1_noreg:.4f} "
    f"(recall {ab_noreg['test']['recall']:.4f}, FPR {ab_noreg['test']['fpr']:.4f}), a small but real loss compared to {f1_ctrl:.4f}."
)
s_e = (
    "(e) Validity caveat: edits to the feature table are not real PDF edits, and none of this measures real-world evasion."
)

what_this_shows = '\\n\\n'.join([s_a, s_b, s_c, s_d, s_e])
assert 'drop' not in s_c.lower() and 'no loss' in s_c.lower()
assert 'falls' in s_a and 'rises' in s_a
print('WHAT THIS SHOWS:\\n' + what_this_shows)
'''

target_idx = None
for i, c in enumerate(nb["cells"]):
    if "WHAT THIS SHOWS" in "".join(c.get("source", [])):
        target_idx = i
        break
assert target_idx is not None, "Could not find A7 cell!"

ns = {"json": json, "REPORTS_DIR": Path("reports")}
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    exec(new_src, ns)
out_text = buf.getvalue()

nb["cells"][target_idx]["source"] = new_src.splitlines(keepends=True)
nb["cells"][target_idx]["outputs"] = [nbformat.v4.new_output("stream", name="stdout", text=out_text)]
nbformat.write(nb, nb_path)
print(f"Updated Cell {target_idx} in {nb_path} without retraining.")
print(out_text)

print("=== reports/domain_shift_demo.csv ===")
df_dom = pd.read_csv("reports/domain_shift_demo.csv")
print(df_dom.to_string(index=False))
print("\nDistinct aliases:", df_dom["alias"].tolist())
assert all(a.startswith("synthetic_") or a.startswith("user_pdf_") for a in df_dom["alias"])
