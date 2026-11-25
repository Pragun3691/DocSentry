"""
Unit tests for DocSentry Inference Engine (src/docsentry_infer.py)
Uses Python standard library unittest to run seamlessly in all environments.
"""
import unittest
import json
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np

from src.docsentry_infer import DocSentryDetector, load_artifacts, predict

PROCESSED_DIR = Path('data/processed')
MODELS_DIR = Path('models')


def assert_prediction_schema(result):
    """Verifies that the output matches the required schema and constraints."""
    assert isinstance(result, dict), "Result must be a dictionary"
    
    # Required keys
    required_keys = ['label', 'calibrated_probability', 'raw_probability', 'review_band', 'top_contributors', 'family_summary']
    for key in required_keys:
        assert key in result, f"Missing required key: {key}"
        
    # Check label
    assert result['label'] in ['benign', 'malicious', 'needs_review'], f"Invalid label: {result['label']}"
    
    # Check probabilities
    assert 0.0 <= result['calibrated_probability'] <= 1.0, "Calibrated probability out of [0, 1] bounds"
    assert 0.0 <= result['raw_probability'] <= 1.0, "Raw probability out of [0, 1] bounds"
    
    # Check review band
    assert isinstance(result['review_band'], list) and len(result['review_band']) == 2, "Review band must be [low, high]"
    assert result['review_band'][0] <= result['review_band'][1], "Review band low must be <= high"
    
    # Check top_contributors
    assert isinstance(result['top_contributors'], list), "top_contributors must be a list"
    assert len(result['top_contributors']) == 8, f"Expected exactly 8 top contributors, got {len(result['top_contributors'])}"
    
    for c in result['top_contributors']:
        assert 'feature' in c, "Contributor missing 'feature'"
        assert 'readable_name' in c, "Contributor missing 'readable_name'"
        assert 'family' in c, "Contributor missing 'family'"
        assert 'shap_value' in c, "Contributor missing 'shap_value'"
        assert 'direction' in c, "Contributor missing 'direction'"
        assert c['direction'] in ['benign', 'malicious'], f"Invalid direction: {c['direction']}"
        
    # Check family_summary
    assert isinstance(result['family_summary'], dict), "family_summary must be a dictionary"
    for fam, summary in result['family_summary'].items():
        assert 'positive_attribution' in summary
        assert 'negative_attribution' in summary
        assert 'net_attribution' in summary


class TestDocSentryInfer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = load_artifacts(models_dir=MODELS_DIR, processed_dir=PROCESSED_DIR)
        X_te = pd.read_parquet(PROCESSED_DIR / 'X_test_tree.parquet')
        y_te = pd.read_parquet(PROCESSED_DIR / 'y_test.parquet')['label'].values
        cls.benign_rows = X_te[y_te == 0].head(5)
        cls.malicious_rows = X_te[y_te == 1].head(5)

    def test_benign_samples(self):
        """Test inference on 5 known benign test rows."""
        for i in range(len(self.benign_rows)):
            row = self.benign_rows.iloc[i]
            res = self.detector.predict(row)
            assert_prediction_schema(res)

    def test_malicious_samples(self):
        """Test inference on 5 known malicious test rows."""
        for i in range(len(self.malicious_rows)):
            row = self.malicious_rows.iloc[i]
            res = self.detector.predict(row)
            assert_prediction_schema(res)

    def test_module_predict(self):
        """Test the module-level predict() function."""
        sample = self.benign_rows.iloc[0]
        res = predict(sample)
        assert_prediction_schema(res)

    def test_schema_mismatch(self):
        """Assert that a missing or corrupted feature vector raises ValueError."""
        corrupted_data = {'general_size': 12345}
        with self.assertRaises(ValueError):
            self.detector.predict(corrupted_data)


if __name__ == '__main__':
    unittest.main()
