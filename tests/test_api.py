"""
Tests for DocSentry FastAPI Backend
===================================
Covers:
- Valid benign PDF upload and full response schema verification
- Non-PDF file renamed to .pdf rejection (400)
- Empty file rejection (400)
- File over size limit rejection (>20 MB -> 413)
- File name containing directory traversal (../) and unicode sanitization
- Fidelity check: API scan results equal direct src.docsentry_extract.scan()
- Temp directory cleanup verification (zero leaked temp files)
- Health and model-info endpoint integrity
"""

import os
import io
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
import src.docsentry_extract as de

BASE_DIR = Path(__file__).resolve().parent.parent
SYNTHETIC_DIR = BASE_DIR / "data/demo_pdfs/synthetic"


class TestDocSentryAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client_ctx = TestClient(app)
        cls.client = cls.client_ctx.__enter__()
        # Verify app is ready
        res = cls.client.get("/health")
        assert res.status_code == 200, "Health check failed on test setup"

    @classmethod
    def tearDownClass(cls):
        cls.client_ctx.__exit__(None, None, None)

    def test_health_endpoint(self):
        """Verifies GET /health returns status ok and model_loaded."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["model_loaded"])

    def test_model_info_endpoint(self):
        """Verifies GET /model-info returns thresholds, review band, test metrics, and limitations."""
        res = self.client.get("/model-info")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("operating_threshold", data)
        self.assertIn("review_band", data)
        self.assertIn("ood_thresholds", data)
        self.assertIn("test_metrics", data)
        self.assertIn("limitations", data)
        self.assertIsInstance(data["limitations"], list)
        self.assertGreater(len(data["limitations"]), 3)

    def test_valid_benign_pdf_and_schema(self):
        """Uploads a valid benign PDF and checks complete response schema."""
        test_file = SYNTHETIC_DIR / "synthetic_a_minimal_blank.pdf"
        self.assertTrue(test_file.exists(), f"Missing test file {test_file}")

        with open(test_file, "rb") as f:
            pdf_bytes = f.read()

        response = self.client.post(
            "/scan",
            files={"file": ("synthetic_a_minimal_blank.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Schema assertions
        required_keys = [
            "file_name", "size", "sha256", "verdict",
            "calibrated_probability", "raw_probability", "review_band",
            "ood_warning", "top_contributors", "family_summary",
            "processing_ms", "reason"
        ]
        for k in required_keys:
            self.assertIn(k, data, f"Missing required response key: {k}")

        self.assertEqual(data["file_name"], "synthetic_a_minimal_blank.pdf")
        self.assertEqual(data["size"], len(pdf_bytes))
        self.assertIn(data["verdict"], ["benign", "malicious", "needs_review"])
        self.assertIsInstance(data["calibrated_probability"], float)
        self.assertIsInstance(data["ood_warning"], bool)
        self.assertIsInstance(data["top_contributors"], list)
        self.assertGreaterEqual(len(data["top_contributors"]), 1)
        self.assertIsInstance(data["family_summary"], dict)
        self.assertIsInstance(data["processing_ms"], (int, float))
        self.assertIsInstance(data["reason"], str)
        self.assertGreater(len(data["reason"]), 10)

        # Check top contributor structure
        first_contrib = data["top_contributors"][0]
        self.assertIn("feature", first_contrib)
        self.assertIn("readable_name", first_contrib)
        self.assertIn("family", first_contrib)
        self.assertIn("shap_value", first_contrib)
        self.assertIn("direction", first_contrib)
        self.assertIn(first_contrib["direction"], ["benign", "malicious"])

    def test_non_pdf_file_renamed_to_pdf(self):
        """Rejects non-PDF file renamed to .pdf with HTTP 400."""
        fake_content = b"This is a plain text file without any PDF magic headers."
        response = self.client.post(
            "/scan",
            files={"file": ("fake_document.pdf", io.BytesIO(fake_content), "application/pdf")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("magic header", response.json()["detail"].lower())

    def test_empty_file(self):
        """Rejects empty file (0 bytes) with HTTP 400."""
        empty_content = b""
        response = self.client.post(
            "/scan",
            files={"file": ("empty.pdf", io.BytesIO(empty_content), "application/pdf")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("empty", response.json()["detail"].lower())

    def test_file_over_size_limit(self):
        """Rejects file exceeding 20 MB with HTTP 413."""
        # Create a payload of 20 MB + 512 bytes
        oversized = b"%PDF-1.4\n" + (b"A" * (20 * 1024 * 1024 + 512))
        response = self.client.post(
            "/scan",
            files={"file": ("large_exploit.pdf", io.BytesIO(oversized), "application/pdf")}
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("20 mb", response.json()["detail"].lower())

    def test_filename_traversal_and_unicode(self):
        """Verifies directory traversal ../ is stripped and unicode names are handled safely."""
        test_file = SYNTHETIC_DIR / "synthetic_a_minimal_blank.pdf"
        pdf_bytes = test_file.read_bytes()

        malicious_filename = "../../../etc/passwd_\u2603_\u6587\u6863.pdf"
        response = self.client.post(
            "/scan",
            files={"file": (malicious_filename, io.BytesIO(pdf_bytes), "application/pdf")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Verify no directory traversal in returned display name
        self.assertNotIn("..", data["file_name"])
        self.assertNotIn("/", data["file_name"])
        self.assertNotIn("\\", data["file_name"])
        self.assertTrue(data["file_name"].endswith(".pdf"))

    def test_scan_fidelity_equals_direct_extract_scan(self):
        """Asserts that API /scan produces exact identical outputs to src.docsentry_extract.scan()."""
        test_file = SYNTHETIC_DIR / "synthetic_d_25_uris.pdf"
        pdf_bytes = test_file.read_bytes()

        # 1. API Scan
        response = self.client.post(
            "/scan",
            files={"file": (test_file.name, io.BytesIO(pdf_bytes), "application/pdf")}
        )
        self.assertEqual(response.status_code, 200)
        api_res = response.json()

        # 2. Direct Scan
        direct_res = de.scan(test_file)

        # 3. Equivalence assertions
        self.assertEqual(api_res["sha256"], direct_res["sha256"])
        self.assertEqual(api_res["size"], direct_res["file_size"])
        self.assertEqual(api_res["verdict"], direct_res["verdict"])
        self.assertAlmostEqual(api_res["calibrated_probability"], direct_res["calibrated_probability"], places=4)
        self.assertAlmostEqual(api_res["raw_probability"], direct_res["raw_probability"], places=4)
        self.assertEqual(api_res["ood_warning"], direct_res["ood_warning"])
        self.assertEqual(api_res["review_band"], direct_res["review_band"])

        # Check top contributor features match in order
        api_feats = [c["feature"] for c in api_res["top_contributors"]]
        direct_feats = [c["feature"] for c in direct_res["top_contributors"]]
        self.assertEqual(api_feats, direct_feats)

    def test_no_temp_files_left_behind(self):
        """Verifies that running scans in memory creates zero persistent leaked files in temp dir."""
        temp_dir = Path(tempfile.gettempdir())
        files_before = set(os.listdir(temp_dir))

        test_file = SYNTHETIC_DIR / "synthetic_a_minimal_blank.pdf"
        pdf_bytes = test_file.read_bytes()

        for _ in range(3):
            res = self.client.post(
                "/scan",
                files={"file": ("test_temp.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
            )
            self.assertEqual(res.status_code, 200)

        files_after = set(os.listdir(temp_dir))
        new_files = files_after - files_before
        # Ensure no docsentry upload files were left behind
        docsentry_leaks = [f for f in new_files if "docsentry" in f.lower() or f.endswith(".pdf")]
        self.assertEqual(docsentry_leaks, [], f"Found leaked temporary files: {docsentry_leaks}")

    def test_scan_same_file_twice_identical(self):
        """Scans the same file twice via POST /scan and asserts results are strictly deterministic."""
        test_file = SYNTHETIC_DIR / "synthetic_a_minimal_blank.pdf"
        pdf_bytes = test_file.read_bytes()

        # Scan 1
        res1 = self.client.post(
            "/scan",
            files={"file": ("synthetic_a_minimal_blank.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
        )
        self.assertEqual(res1.status_code, 200)
        data1 = res1.json()

        # Scan 2
        res2 = self.client.post(
            "/scan",
            files={"file": ("synthetic_a_minimal_blank.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
        )
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()

        # Compare deterministic fields
        deterministic_keys = [
            "file_name", "size", "sha256", "verdict",
            "calibrated_probability", "raw_probability", "review_band",
            "ood_warning", "top_contributors", "family_summary", "reason"
        ]
        for key in deterministic_keys:
            self.assertEqual(data1[key], data2[key], f"Scan non-deterministic mismatch on {key}")

    def test_synthetic_a_and_c_feature_vectors_differ(self):
        """Scans synthetic_a and synthetic_c and asserts their feature vectors and scores differ."""
        file_a = SYNTHETIC_DIR / "synthetic_a_minimal_blank.pdf"
        file_c = SYNTHETIC_DIR / "synthetic_c_20_page_report.pdf"
        self.assertTrue(file_a.exists(), f"Missing {file_a}")
        self.assertTrue(file_c.exists(), f"Missing {file_c}")

        # Scan via API
        res_a = self.client.post(
            "/scan",
            files={"file": (file_a.name, io.BytesIO(file_a.read_bytes()), "application/pdf")}
        )
        res_c = self.client.post(
            "/scan",
            files={"file": (file_c.name, io.BytesIO(file_c.read_bytes()), "application/pdf")}
        )
        self.assertEqual(res_a.status_code, 200)
        self.assertEqual(res_c.status_code, 200)
        data_a = res_a.json()
        data_c = res_c.json()

        # Hash, size, and predictions must differ
        self.assertNotEqual(data_a["sha256"], data_c["sha256"])
        self.assertNotEqual(data_a["size"], data_c["size"])
        self.assertNotEqual(data_a["raw_probability"], data_c["raw_probability"])
        self.assertNotEqual(data_a["verdict"], data_c["verdict"])

        # Extract features directly and assert feature vectors differ substantially
        extractor = de.DocSentryFeatureExtractor(processed_dir=BASE_DIR / "data/processed")
        df_a = extractor.extract(file_a)
        df_c = extractor.extract(file_c)

        diff_count = (df_a.values != df_c.values).sum()
        self.assertGreater(diff_count, 100, f"Expected >100 differing features, found {diff_count}")


if __name__ == "__main__":
    unittest.main()
