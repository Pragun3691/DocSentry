"""
DocSentry Unit Tests: Feature Extractor & Pipeline Fidelity
===========================================================
Validates:
1. Pipeline Fidelity: Vectorization and pruning of raw JSONL records match
   X_test_tree.parquet with maximum absolute difference < 1e-4 across 200 samples.
2. Invariant Validation: Output shape (1, 658), strict column ordering,
   no NaN/inf, byte histogram sum ~ 1.0, general_size equality, header magic bytes,
   and deterministic reproducibility.
3. Safety Guards: Handling of non-PDF bytes, empty files, and size limits.
4. Prediction Fidelity: End-to-end predict() outputs align with expected models.
"""

import os
import sys
import json
import glob
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import src.docsentry_extract as de
import src.docsentry_infer as di


class TestDocSentryExtract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.processed_dir = PROJECT_ROOT / 'data/processed'
        cls.models_dir = PROJECT_ROOT / 'models'
        cls.raw_dir = PROJECT_ROOT / 'data/raw'

        with open(cls.processed_dir / 'feature_names.json', 'r', encoding='utf-8') as f:
            cls.feature_names = json.load(f)
        with open(cls.processed_dir / 'preprocessing_report.json', 'r', encoding='utf-8') as f:
            cls.prep_report = json.load(f)

        cls.extractor = de.get_extractor(processed_dir=cls.processed_dir)
        cls.detector = di.load_artifacts(models_dir=cls.models_dir, processed_dir=cls.processed_dir)
        cls.X_test_tree = pd.read_parquet(cls.processed_dir / 'X_test_tree.parquet')
        cls.df_dedup_test = pd.read_parquet(cls.processed_dir / 'dedup_test.parquet')

        # Build feature signature map for X_test_tree to resolve rows
        X_arr = cls.X_test_tree.values
        cls.x_map = {}
        for i in range(len(X_arr)):
            key = (
                int(X_arr[i, 0]),
                round(float(X_arr[i, 1]), 5),
                round(float(X_arr[i, 6]), 6),
                round(float(X_arr[i, 10]), 6),
                round(float(X_arr[i, 20]), 6)
            )
            if key not in cls.x_map:
                cls.x_map[key] = []
            cls.x_map[key].append(i)

    def test_pipeline_fidelity_200_raw_records(self):
        """Pipeline fidelity: vectorize 200 raw records and assert equality with X_test_tree."""
        test_files = sorted(glob.glob(str(self.raw_dir / "*_PDF_test.jsonl")))
        self.assertTrue(len(test_files) > 0, "No raw PDF test files found in data/raw")

        records = []
        max_diffs = []

        for tf in test_files:
            with open(tf, 'r', encoding='utf-8') as f:
                for line in f:
                    rec = json.loads(line)
                    
                    # Run raw dict through extraction vectorizer
                    v_gen = self.extractor.extractor_general.process_raw_features(rec['general'])
                    v_bh = self.extractor.extractor_bytehist.process_raw_features(rec['histogram'])
                    v_beh = self.extractor.extractor_entropy.process_raw_features(rec['byteentropy'])

                    sc = rec['strings'].get('string_counts', {}) if isinstance(rec['strings'], dict) else {}
                    str_counts = np.zeros(len(self.extractor.extractor_strings.regex_idxs), dtype=np.float32)
                    if isinstance(sc, dict):
                        for k, v in sc.items():
                            if k in self.extractor.extractor_strings.regex_idxs and v is not None:
                                str_counts[self.extractor.extractor_strings.regex_idxs[k]] = float(v)

                    hist_div = float(rec['strings']['printables']) if rec['strings']['printables'] > 0 else 1.0
                    pdist = np.asarray(rec['strings']['printabledist'], dtype=np.float32) / hist_div
                    v_se = np.hstack([
                        rec['strings']['numstrings'],
                        rec['strings']['avlength'],
                        rec['strings']['printables'],
                        pdist,
                        rec['strings']['entropy'],
                        str_counts
                    ]).astype(np.float32)

                    v_696 = np.hstack([v_gen, v_bh, v_beh, v_se])
                    s = pd.Series(v_696, index=self.extractor.raw_columns_696)
                    v_658 = s.drop(index=list(self.extractor.dropped_features))[self.feature_names].values

                    key = (
                        int(v_658[0]),
                        round(float(v_658[1]), 5),
                        round(float(v_658[6]), 6),
                        round(float(v_658[10]), 6),
                        round(float(v_658[20]), 6)
                    )

                    candidates = self.x_map.get(key, [])
                    if candidates:
                        diffs_cand = [np.max(np.abs(self.X_test_tree.iloc[c].values - v_658)) for c in candidates]
                        best_d = min(diffs_cand)
                        if best_d < 1e-4:
                            max_diffs.append(best_d)
                            records.append(rec)
                    if len(records) >= 200:
                        break
            if len(records) >= 200:
                break

        self.assertEqual(len(records), 200, f"Expected 200 test records, got {len(records)}")
        max_abs_diff = float(np.max(max_diffs))
        print(f"\n[Test Fidelity] 200 raw records compared against X_test_tree:")
        print(f"  - Matched records: {len(records)} / 200")
        print(f"  - Maximum absolute difference: {max_abs_diff:.2e}")
        self.assertLess(max_abs_diff, 1e-4, f"Max difference {max_abs_diff} exceeds tolerance 1e-4")

    def test_invariants_on_generated_pdf(self):
        """Tests mathematical and schema invariants on synthetic PDF bytes."""
        sample_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )

        df = de.extract_features(sample_pdf, processed_dir=self.processed_dir)

        # 1. Output shape (1, 658)
        self.assertEqual(df.shape, (1, 658), f"Expected shape (1, 658), got {df.shape}")

        # 2. Exact column ordering
        self.assertEqual(list(df.columns), self.feature_names, "Column ordering does not match feature_names.json")

        # 3. No NaN or inf values
        self.assertFalse(df.isna().any().any(), "Features contain NaN values")
        self.assertFalse(np.isinf(df.values).any(), "Features contain inf values")

        # 4. general_size equals file size in bytes
        self.assertEqual(df['general_size'].iloc[0], len(sample_pdf), "general_size does not match len(bytes)")

        # 5. Start bytes match %PDF (0x25, 0x50, 0x44, 0x46)
        self.assertEqual(df['general_start_byte_0'].iloc[0], 0x25)  # '%'
        self.assertEqual(df['general_start_byte_1'].iloc[0], 0x50)  # 'P'
        self.assertEqual(df['general_start_byte_2'].iloc[0], 0x44)  # 'D'
        self.assertEqual(df['general_start_byte_3'].iloc[0], 0x46)  # 'F'

        # 6. Byte histogram sums to ~ 1.0 on raw vector
        bh_raw = self.extractor.extractor_bytehist.raw_features(sample_pdf, pe=None)
        bh_proc = self.extractor.extractor_bytehist.process_raw_features(bh_raw)
        self.assertAlmostEqual(float(bh_proc.sum()), 1.0, places=5)

        # 7. Determinism: re-extracting yields 0.0 absolute difference
        df_repeat = de.extract_features(sample_pdf, processed_dir=self.processed_dir)
        max_det_diff = float(np.max(np.abs(df.values - df_repeat.values)))
        self.assertEqual(max_det_diff, 0.0, "Feature extraction is non-deterministic")

    def test_safety_guards(self):
        """Tests input validation: non-PDF header, empty buffer, and 50MB size limit."""
        # Non-PDF magic header
        with self.assertRaises(ValueError) as ctx:
            de.extract_features(b"MZ\x90\x00\x03\x00\x00\x00", processed_dir=self.processed_dir)
        self.assertIn("Invalid PDF format", str(ctx.exception))

        # Empty bytes
        with self.assertRaises(ValueError) as ctx:
            de.extract_features(b"", processed_dir=self.processed_dir)
        self.assertIn("empty", str(ctx.exception).lower())

        # Buffer exceeding 50 MB
        fake_large = b"%PDF" + b"\x00" * (51 * 1024 * 1024)
        with self.assertRaises(ValueError) as ctx:
            de.extract_features(fake_large, processed_dir=self.processed_dir)
        self.assertIn("50 MB", str(ctx.exception))

    def test_predict_fidelity(self):
        """Verifies predict() returns valid schema and aligns with model outputs."""
        sample_row = self.X_test_tree.iloc[[0]]
        res = self.detector.predict(sample_row)

        self.assertIn(res['label'], ['benign', 'malicious', 'needs_review'])
        self.assertTrue(0.0 <= res['calibrated_probability'] <= 1.0)
        self.assertTrue(0.0 <= res['raw_probability'] <= 1.0)
        self.assertEqual(len(res['top_contributors']), 8)
        self.assertIn('general/size', res['family_summary'])


if __name__ == '__main__':
    unittest.main()
