# DocSentry Synthetic Test PDFs
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
