"""
DocSentry Synthetic PDF Generator
=================================
Generates 6 clean, harmless synthetic test PDFs using pure Python byte structures
(no third-party PDF authoring tools or malware libraries required).

Files created in data/demo_pdfs/synthetic/:
(a) synthetic_a_minimal_blank.pdf  (~350 bytes)
(b) synthetic_b_one_page_text.pdf   (Single page with visible text stream)
(c) synthetic_c_20_page_report.pdf  (Multi-page report with 20 distinct pages)
(d) synthetic_d_25_uris.pdf         (Contains 25 external HTTPS links with /URI annotations)
(e) synthetic_e_embedded_js.pdf     (Contains harmless embedded JS: app.alert("hello"))
(f) synthetic_f_large_5mb.pdf       (Valid PDF exceeding 5 MB in file size)
"""

import os
from pathlib import Path

OUT_DIR = Path("data/demo_pdfs/synthetic")
OUT_DIR.mkdir(parents=True, exist_ok=True)
USER_DIR = Path("data/demo_pdfs/user")
USER_DIR.mkdir(parents=True, exist_ok=True)


def build_pdf(objects, root_obj_id=1):
    """
    Assembles a valid PDF document with xref table and trailer from a list of objects.
    objects is a list of (obj_id, obj_body_bytes).
    """
    # Header
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}

    for obj_id, body in objects:
        offsets[obj_id] = len(out)
        out.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        out.extend(body)
        if not body.endswith(b"\n"):
            out.extend(b"\n")
        out.extend(b"endobj\n")

    # Xref table
    xref_offset = len(out)
    max_id = max(offsets.keys()) if offsets else 0
    out.extend(f"xref\n0 {max_id + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for i in range(1, max_id + 1):
        if i in offsets:
            out.extend(f"{offsets[i]:010d} 00000 n \n".encode("ascii"))
        else:
            out.extend(b"0000000000 65535 f \n")

    # Trailer
    out.extend(
        f"trailer\n<< /Size {max_id + 1} /Root {root_obj_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


# ----------------------------------------------------------------------
# (a) Minimal Blank PDF (~350 bytes)
# ----------------------------------------------------------------------
def make_minimal_blank():
    objs = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"),
    ]
    return build_pdf(objs, root_obj_id=1)


# ----------------------------------------------------------------------
# (b) 1-Page Text PDF
# ----------------------------------------------------------------------
def make_one_page_text():
    text_content = (
        b"BT\n"
        b"/F1 18 Tf\n"
        b"72 700 Td\n"
        b"(DocSentry System Evaluation - Single Page Text Document) Tj\n"
        b"/F1 12 Tf\n"
        b"0 -30 Td\n"
        b"(This is a legitimate benign PDF document containing typical formatting and text.) Tj\n"
        b"0 -20 Td\n"
        b"(It demonstrates baseline byte histogram and string character distributions.) Tj\n"
        b"ET\n"
    )
    stream_bytes = f"<< /Length {len(text_content)} >>\nstream\n".encode("ascii") + text_content + b"endstream"

    objs = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        (4, stream_bytes),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
    ]
    return build_pdf(objs, root_obj_id=1)


# ----------------------------------------------------------------------
# (c) 20-Page Text Report
# ----------------------------------------------------------------------
def make_20_page_report():
    page_ids = [i + 3 for i in range(20)]
    stream_id = 23
    font_id = 24

    text_content = (
        b"BT\n/F1 14 Tf\n72 720 Td (DocSentry Comprehensive Multi-Page Security Report) Tj\n"
        b"/F1 10 Tf\n0 -25 Td (Page content demonstrating multi-page benign structural complexity.) Tj\nET\n"
    )
    stream_bytes = f"<< /Length {len(text_content)} >>\nstream\n".encode("ascii") + text_content + b"endstream"

    kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
    objs = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, f"<< /Type /Pages /Kids [{kids_str}] /Count 20 >>".encode("ascii")),
    ]

    for pid in page_ids:
        page_dict = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {stream_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>".encode("ascii")
        objs.append((pid, page_dict))

    objs.append((stream_id, stream_bytes))
    objs.append((font_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

    return build_pdf(objs, root_obj_id=1)


# ----------------------------------------------------------------------
# (d) 25 External HTTPS Links (/URI)
# ----------------------------------------------------------------------
def make_25_uris():
    # Build 25 link annotations
    annot_ids = [10 + i for i in range(25)]
    annot_refs = " ".join(f"{aid} 0 R" for aid in annot_ids)

    text_lines = [b"BT\n/F1 14 Tf\n72 750 Td (Document with 25 Verified External HTTPS Links) Tj\n/F1 9 Tf\n"]
    y_pos = 720
    for i in range(25):
        text_lines.append(f"0 -24 Td (Link {i+1}: https://docsentry.security.edu/resource/ref_{i+1:02d}) Tj\n".encode("ascii"))
    text_lines.append(b"ET\n")
    text_content = b"".join(text_lines)
    stream_bytes = f"<< /Length {len(text_content)} >>\nstream\n".encode("ascii") + text_content + b"endstream"

    objs = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [{annot_refs}] /Resources << /Font << /F1 5 0 R >> >> >>".encode("ascii")),
        (4, stream_bytes),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
    ]

    for i, aid in enumerate(annot_ids):
        uri_str = f"https://docsentry.security.edu/resource/ref_{i+1:02d}"
        annot_dict = (
            f"<< /Type /Annot /Subtype /Link /Rect [72 {y_pos - 15} 400 {y_pos + 5}] "
            f"/Border [0 0 0] /A << /S /URI /URI ({uri_str}) >> >>"
        ).encode("ascii")
        objs.append((aid, annot_dict))
        y_pos -= 24

    return build_pdf(objs, root_obj_id=1)


# ----------------------------------------------------------------------
# (e) Harmless Embedded JS: app.alert("hello")
# ----------------------------------------------------------------------
def make_embedded_js():
    text_content = (
        b"BT\n/F1 14 Tf\n72 700 Td (Document with Harmless Embedded JavaScript Action) Tj\n"
        b"/F1 10 Tf\n0 -25 Td (Contains harmless /JavaScript action triggering an alert box on load.) Tj\nET\n"
    )
    stream_bytes = f"<< /Length {len(text_content)} >>\nstream\n".encode("ascii") + text_content + b"endstream"

    # Catalog includes /OpenAction pointing to JavaScript action
    objs = [
        (1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        (4, stream_bytes),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
        (6, b'<< /Type /Action /S /JavaScript /JS (app.alert("hello");) >>'),
    ]
    return build_pdf(objs, root_obj_id=1)


# ----------------------------------------------------------------------
# (f) PDF > 5 MB
# ----------------------------------------------------------------------
def make_large_5mb():
    # 5.25 MB payload stream (5,500,000 bytes)
    padding_size = 5_500_000
    # Repeating harmless text pattern
    pattern = b"DocSentry-Safe-Padding-Block-0123456789\n"
    reps = (padding_size // len(pattern)) + 1
    stream_data = (pattern * reps)[:padding_size]

    text_content = (
        b"BT\n/F1 14 Tf\n72 700 Td (Large Benign File Size Benchmark Document - 5.25 MB) Tj\n"
        b"/F1 10 Tf\n0 -25 Td (Demonstrates static feature extraction scalability on files > 5 MB.) Tj\nET\n"
    )

    stream_display = f"<< /Length {len(text_content)} >>\nstream\n".encode("ascii") + text_content + b"endstream"
    stream_large = f"<< /Length {len(stream_data)} >>\nstream\n".encode("ascii") + stream_data + b"endstream"

    objs = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents [4 0 R 6 0 R] /Resources << /Font << /F1 5 0 R >> >> >>"),
        (4, stream_display),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
        (6, stream_large),
    ]
    return build_pdf(objs, root_obj_id=1)


def generate_all():
    print("Generating synthetic harmless test PDFs...")

    files = [
        ("synthetic_a_minimal_blank.pdf", make_minimal_blank()),
        ("synthetic_b_one_page_text.pdf", make_one_page_text()),
        ("synthetic_c_20_page_report.pdf", make_20_page_report()),
        ("synthetic_d_25_uris.pdf", make_25_uris()),
        ("synthetic_e_embedded_js.pdf", make_embedded_js()),
        ("synthetic_f_large_5mb.pdf", make_large_5mb()),
    ]

    for fname, data in files:
        fpath = OUT_DIR / fname
        with open(fpath, "wb") as f:
            f.write(data)
        size_kb = len(data) / 1024
        print(f"  Created: {fname:<35} Size: {size_kb:>9.1f} KB ({len(data):,} bytes)")

    # Write README in synthetic directory
    readme_content = """# DocSentry Synthetic Test PDFs
This directory contains 6 handcrafted, strictly benign synthetic PDF files
designed to probe specific static feature boundaries and detector behaviors.
All files were generated using pure Python byte structures without third-party
authoring software or active exploit payloads.

### Catalog of Test Documents:
1. `synthetic_a_minimal_blank.pdf` (~350 bytes):
   - Tests model behavior on minimal structure with near-zero string content.
2. `synthetic_b_one_page_text.pdf` (~820 bytes):
   - Baseline single-page benign document with typical ASCII text distribution.
3. `synthetic_c_20_page_report.pdf` (~4.8 KB):
   - Multi-page document testing structural scalability with 20 page dictionary objects.
4. `synthetic_d_25_uris.pdf` (~4.5 KB):
   - Contains 25 external HTTPS link annotations (`/URI`). Probes the model's sensitivity to `/URI` keywords.
5. `synthetic_e_embedded_js.pdf` (~980 bytes):
   - Contains a harmless `/OpenAction` JavaScript payload (`app.alert("hello")`). Probes keyword sensitivity to `/JavaScript`.
6. `synthetic_f_large_5mb.pdf` (~5.25 MB):
   - Valid large PDF exceeding 5 MB to verify static extraction speed and stability on large binaries.
"""
    with open(OUT_DIR / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)

    # Write README in user directory
    user_readme = """# User PDF Drop Directory
Place any real-world PDF files you wish to analyze in this directory (`data/demo_pdfs/user/`).
Run `python scripts/scan_pdfs.py --dir data/demo_pdfs/user` or execute `notebooks/06_real_pdf_demo.ipynb`
to extract static features, compute calibrated probabilities, assess review band classification,
and generate local SHAP explanations.
"""
    with open(USER_DIR / "README.md", "w", encoding="utf-8") as f:
        f.write(user_readme)

    print("All synthetic test documents and README files successfully generated.")


if __name__ == "__main__":
    generate_all()
