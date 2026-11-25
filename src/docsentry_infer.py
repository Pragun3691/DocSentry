"""
DocSentry Inference & Explainability Module
Provides production inference, probability calibration, selective review-band triage,
and local SHAP attribution explanations for PDF malware detection.
"""
import json
from pathlib import Path
from typing import Dict, Any, Union, List

import numpy as np
import pandas as pd
import joblib
import shap


def decode_feature_name(fname: str) -> str:
    """Decodes feature names into human-readable ASCII and byte-entropy intervals."""
    if fname.startswith('strings_printabledist_'):
        idx = int(fname.split('_')[-1])
        ascii_code = idx + 32
        char = chr(ascii_code) if 32 <= ascii_code <= 126 else f"0x{ascii_code:02x}"
        char_desc = "SPACE" if char == ' ' else f"'{char}'"
        return f"{fname} [{char_desc}]"
    elif fname.startswith('byte_entropy_'):
        parts = fname.split('_')
        idx1 = int(parts[2])
        idx2 = int(parts[3])
        ent_low = idx1 * 0.5
        ent_high = (idx1 + 1) * 0.5
        b_low = idx2 * 16
        b_high = idx2 * 16 + 15
        return f"byte-entropy: entropy bin {idx1} ({ent_low:.1f}-{ent_high:.1f} bits), bytes 0x{b_low:02X}-0x{b_high:02X}"
    elif fname.startswith('byte_hist_'):
        byte_val = int(fname.split('_')[-1])
        return f"byte_hist_{byte_val} [0x{byte_val:02X}]"
    return fname


def assign_feature_family(fname: str) -> str:
    """Assigns static feature to its conceptual feature family."""
    if fname.startswith('general_'):
        return 'general/size'
    elif fname.startswith('byte_hist_'):
        return 'byte histogram'
    elif fname.startswith('byte_entropy_'):
        return 'byte-entropy histogram'
    elif fname in ['strings_numstrings', 'strings_avlength', 'strings_printables', 'strings_entropy']:
        return 'string scalars'
    elif fname.startswith('strings_printabledist_'):
        return 'printable-character distribution'
    elif fname.startswith('strings_regex_'):
        return 'regex indicators'
    return 'other'


class DocSentryDetector:
    """Production inference detector for DocSentry."""

    def __init__(self, models_dir: Union[str, Path] = 'models', processed_dir: Union[str, Path] = 'data/processed'):
        self.models_dir = Path(models_dir)
        self.processed_dir = Path(processed_dir)
        self.model = None
        self.calibrator = None
        self.thresholds = None
        self.feature_names = None
        self.explainer = None
        self._load_artifacts()

    def _load_artifacts(self):
        # 1. Feature schema
        schema_path = self.processed_dir / 'feature_names.json'
        if not schema_path.exists():
            raise FileNotFoundError(f"Feature names schema not found at {schema_path}")
        with open(schema_path, 'r') as f:
            self.feature_names = json.load(f)

        # 2. Champion model
        model_path = self.models_dir / 'best_model.joblib'
        if not model_path.exists():
            model_path = self.models_dir / 'xgboost.joblib'
        if not model_path.exists():
            raise FileNotFoundError(f"Model artifact not found in {self.models_dir}")
        self.model = joblib.load(model_path)

        # 3. Calibrator
        cal_path = self.models_dir / 'calibrator.joblib'
        if not cal_path.exists():
            raise FileNotFoundError(f"Calibrator artifact not found at {cal_path}")
        self.calibrator = joblib.load(cal_path)

        # 4. Thresholds & Review Band configuration
        thresh_path = self.models_dir / 'thresholds.json'
        if not thresh_path.exists():
            raise FileNotFoundError(f"Thresholds configuration not found at {thresh_path}")
        with open(thresh_path, 'r') as f:
            self.thresholds = json.load(f)

        # 5. TreeExplainer for XGBoost (fast local marginal path attribution)
        self.explainer = shap.TreeExplainer(self.model)

    def predict(self, features: Union[Dict[str, float], pd.Series, pd.DataFrame, np.ndarray]) -> Dict[str, Any]:
        """
        Executes calibrated prediction, selective review band triage, and local SHAP explanations.

        Parameters
        ----------
        features : dict, pd.Series, pd.DataFrame, or np.ndarray
            Static feature values for a single document. Must contain exactly the 658 model features.

        Returns
        -------
        dict
            Structured operational report containing:
            - label: 'benign' | 'malicious' | 'needs_review'
            - calibrated_probability: float
            - review_band: [low, high]
            - top_contributors: list of top 8 features with attribution & direction
            - family_summary: dict of summed positive/negative attributions by feature family
        """
        # Feature vector alignment
        if isinstance(features, dict):
            missing = set(self.feature_names) - set(features.keys())
            if missing:
                raise ValueError(f"Input features missing {len(missing)} required features. First missing: {list(missing)[:5]}")
            row_data = [features[col] for col in self.feature_names]
            X_input = pd.DataFrame([row_data], columns=self.feature_names)
        elif isinstance(features, pd.Series):
            missing = set(self.feature_names) - set(features.index)
            if missing:
                raise ValueError(f"Input features missing {len(missing)} required features. First missing: {list(missing)[:5]}")
            X_input = pd.DataFrame([features[self.feature_names].values], columns=self.feature_names)
        elif isinstance(features, pd.DataFrame):
            if list(features.columns) != self.feature_names:
                missing = set(self.feature_names) - set(features.columns)
                if missing:
                    raise ValueError(f"Input DataFrame missing {len(missing)} required columns.")
                X_input = features[self.feature_names].iloc[[0]].copy()
            else:
                X_input = features.iloc[[0]].copy()
        elif isinstance(features, (np.ndarray, list)):
            arr = np.asarray(features)
            if arr.ndim == 1:
                if len(arr) != len(self.feature_names):
                    raise ValueError(f"Expected array of length {len(self.feature_names)}, got {len(arr)}.")
                X_input = pd.DataFrame([arr], columns=self.feature_names)
            else:
                if arr.shape[1] != len(self.feature_names):
                    raise ValueError(f"Expected array with {len(self.feature_names)} columns, got {arr.shape[1]}.")
                X_input = pd.DataFrame([arr[0]], columns=self.feature_names)
        else:
            raise TypeError(f"Unsupported features type: {type(features)}")

        # 1. Raw and calibrated probabilities
        p_raw = float(self.model.predict_proba(X_input)[0, 1])
        p_cal = float(self.calibrator.predict(np.array([p_raw]))[0])

        # 2. Decision classification via review band
        band_low = float(self.thresholds['review_band']['low'])
        band_high = float(self.thresholds['review_band']['high'])

        if p_cal < band_low:
            decision_label = 'benign'
        elif p_cal > band_high:
            decision_label = 'malicious'
        else:
            decision_label = 'needs_review'

        # 3. Out-Of-Distribution (OOD) check on 0.5% and 99.5% train percentiles
        val_size = float(X_input['general_size'].iloc[0]) if 'general_size' in X_input else 0.0
        val_ns = float(X_input['strings_numstrings'].iloc[0]) if 'strings_numstrings' in X_input else 0.0
        ood_cfg = self.thresholds.get('ood_thresholds', {
            'size_p05': 358.0,
            'size_p995': 30602208.0,
            'numstrings_p05': 17.0,
            'numstrings_p995': 181974.5
        })
        ood_warning = bool(
            val_size < ood_cfg['size_p05'] or
            val_size > ood_cfg['size_p995'] or
            val_ns < ood_cfg['numstrings_p05'] or
            val_ns > ood_cfg['numstrings_p995']
        )

        # 4. Local SHAP Attribution
        shap_vals = self.explainer(X_input).values[0]

        # Top 8 contributors by absolute SHAP attribution
        abs_indices = np.argsort(np.abs(shap_vals))[::-1][:8]
        top_contributors: List[Dict[str, Any]] = []

        for idx in abs_indices:
            feat_name = self.feature_names[idx]
            sv = float(shap_vals[idx])
            top_contributors.append({
                'feature': feat_name,
                'readable_name': decode_feature_name(feat_name),
                'family': assign_feature_family(feat_name),
                'shap_value': round(sv, 4),
                'direction': 'malicious' if sv > 0 else 'benign'
            })

        # Family attribution summary
        family_summary: Dict[str, Dict[str, float]] = {}
        for fname, sv in zip(self.feature_names, shap_vals):
            fam = assign_feature_family(fname)
            if fam not in family_summary:
                family_summary[fam] = {'positive_attribution': 0.0, 'negative_attribution': 0.0, 'net_attribution': 0.0}
            if sv > 0:
                family_summary[fam]['positive_attribution'] += float(sv)
            else:
                family_summary[fam]['negative_attribution'] += float(sv)
            family_summary[fam]['net_attribution'] += float(sv)

        # Round values for cleanliness
        for fam in family_summary:
            family_summary[fam] = {k: round(v, 4) for k, v in family_summary[fam].items()}

        return {
            'label': decision_label,
            'calibrated_probability': round(p_cal, 4),
            'raw_probability': round(p_raw, 4),
            'review_band': [round(band_low, 4), round(band_high, 4)],
            'ood_warning': ood_warning,
            'top_contributors': top_contributors,
            'family_summary': family_summary
        }


# Module-level convenience functions
_DEFAULT_DETECTOR = None

def load_artifacts(models_dir: Union[str, Path] = 'models', processed_dir: Union[str, Path] = 'data/processed') -> DocSentryDetector:
    """Loads all model and metadata artifacts and initializes the detector."""
    global _DEFAULT_DETECTOR
    _DEFAULT_DETECTOR = DocSentryDetector(models_dir=models_dir, processed_dir=processed_dir)
    return _DEFAULT_DETECTOR

def predict(features: Union[Dict[str, float], pd.Series, pd.DataFrame, np.ndarray]) -> Dict[str, Any]:
    """Module-level prediction entrypoint."""
    global _DEFAULT_DETECTOR
    if _DEFAULT_DETECTOR is None:
        _DEFAULT_DETECTOR = load_artifacts()
    return _DEFAULT_DETECTOR.predict(features)
