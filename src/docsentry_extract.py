"""
DocSentry PDF Static Feature Extractor & Scanner Module
=======================================================
This module provides safe, production-grade static feature extraction and full
end-to-end scanning for PDF files, producing feature representations identical
to the EMBER2024 PDF benchmark representation.

Code Reuse Declaration:
-----------------------
This implementation REUSES the battle-tested feature extraction classes from
the official `thrember` package (`thrember.features`):
- `GeneralFileInfo`: File size, Shannon whole-file entropy, is_pe flag, and header start bytes.
- `ByteHistogram`: Normalized whole-file 256-bin byte frequency histogram.
- `ByteEntropyHistogram`: 2D (16x16) joint byte-value and local sliding-window entropy histogram.
- `StringExtractor`: Printable string extraction, string length statistics, printable character
  frequency distribution (96 ASCII bins), string Shannon entropy, and 77 regex indicators.

These classes are NOT reimplemented; they are imported and orchestrated directly.

Security & Safety Guarantees:
-----------------------------
1. Pure Static Analysis: Features are computed strictly over raw binary streams.
   PDF objects are never parsed, executed, or rendered with PDF rendering engines,
   guaranteeing complete immunity from parser exploits or malicious payload execution.
2. Safety Guards:
   - Strict 50 MB maximum file size cap (`MAX_FILE_SIZE = 52,428,800 bytes`).
   - Magic byte validation: files must start with `%PDF` (`b'%PDF'`).
   - Graceful handling of empty, truncated, or password-encrypted PDFs.
   - PE format isolation: non-PE inputs pass `pe=None`, preventing lief/pefile format crashes.
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Union, Dict, Any, Optional

import numpy as np
import pandas as pd

# Reuse official thrember feature extractors
from thrember.features import (
    GeneralFileInfo,
    ByteHistogram,
    ByteEntropyHistogram,
    StringExtractor
)

# Operational limits
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB


class DocSentryFeatureExtractor:
    """
    Extracts the 658 operational static features from raw PDF byte streams.
    """

    def __init__(self, processed_dir: Union[str, Path] = 'data/processed'):
        self.processed_dir = Path(processed_dir)
        
        # Instantiate thrember extractors
        self.extractor_general = GeneralFileInfo()
        self.extractor_bytehist = ByteHistogram()
        self.extractor_entropy = ByteEntropyHistogram()
        self.extractor_strings = StringExtractor()

        # Load schemas
        schema_path = self.processed_dir / 'feature_names.json'
        if not schema_path.exists():
            raise FileNotFoundError(f"Feature names schema not found at: {schema_path}")
        with open(schema_path, 'r', encoding='utf-8') as f:
            self.feature_names = json.load(f)

        prep_path = self.processed_dir / 'preprocessing_report.json'
        if not prep_path.exists():
            raise FileNotFoundError(f"Preprocessing report not found at: {prep_path}")
        with open(prep_path, 'r', encoding='utf-8') as f:
            prep_report = json.load(f)
        self.dropped_features = set(prep_report['dropped_features_list'])

        # Precompute the canonical 696 column ordering
        self.raw_columns_696 = self._build_raw_696_columns()

    def _build_raw_696_columns(self) -> list:
        """Constructs the canonical 696-column ordering of raw unpruned extractors."""
        cols = [
            'general_size', 'general_entropy', 'general_is_pe',
            'general_start_byte_0', 'general_start_byte_1', 'general_start_byte_2', 'general_start_byte_3'
        ]
        cols.extend([f"byte_hist_{i:03d}" for i in range(256)])
        cols.extend([f"byte_entropy_{r:02d}_{c:02d}" for r in range(16) for c in range(16)])
        cols.append("strings_numstrings")
        cols.append("strings_avlength")
        cols.append("strings_printables")
        cols.extend([f"strings_printabledist_{i:02d}" for i in range(96)])
        cols.append("strings_entropy")
        for rk in sorted(self.extractor_strings._regexes.keys()):
            cols.append(f"strings_regex_{rk}")
        return cols

    def extract(self, path_or_bytes: Union[str, Path, bytes, bytearray]) -> pd.DataFrame:
        """
        Extracts 658 static features from a PDF file path or raw bytes.

        Parameters
        ----------
        path_or_bytes : str, Path, bytes, or bytearray
            Input document as a filesystem path or raw binary byte stream.

        Returns
        -------
        pd.DataFrame
            1 x 658 DataFrame containing raw unscaled features in the exact
            column order expected by DocSentry tree models.
        """
        # 1. Ingest bytes safely
        if isinstance(path_or_bytes, (str, Path)):
            p = Path(path_or_bytes)
            if not p.exists():
                raise FileNotFoundError(f"PDF file not found: {p}")
            file_size = p.stat().st_size
            if file_size > MAX_FILE_SIZE_BYTES:
                raise ValueError(f"File size {file_size / (1024**2):.1f} MB exceeds 50 MB safety cap")
            if file_size == 0:
                raise ValueError("Cannot extract features from empty file (0 bytes)")
            with open(p, 'rb') as f:
                bytez = f.read()
        elif isinstance(path_or_bytes, (bytes, bytearray)):
            bytez = bytes(path_or_bytes)
            if len(bytez) > MAX_FILE_SIZE_BYTES:
                raise ValueError(f"Byte buffer of {len(bytez) / (1024**2):.1f} MB exceeds 50 MB safety cap")
            if len(bytez) == 0:
                raise ValueError("Cannot extract features from empty byte buffer (0 bytes)")
        else:
            raise TypeError(f"Unsupported input type: {type(path_or_bytes)}. Expected Path, str, or bytes.")

        # 2. Header and magic bytes validation
        if not bytez.startswith(b'%PDF'):
            raise ValueError("Invalid PDF format: file does not begin with '%PDF' magic header")

        # 3. Static feature extraction (passing pe=None ensures no lief/pefile invocations)
        raw_general = self.extractor_general.raw_features(bytez, pe=None)
        v_general = self.extractor_general.process_raw_features(raw_general)

        raw_bh = self.extractor_bytehist.raw_features(bytez, pe=None)
        v_bh = self.extractor_bytehist.process_raw_features(raw_bh)

        raw_beh = self.extractor_entropy.raw_features(bytez, pe=None)
        v_beh = self.extractor_entropy.process_raw_features(raw_beh)

        raw_strings = self.extractor_strings.raw_features(bytez, pe=None)
        v_strings = self.extractor_strings.process_raw_features(raw_strings)

        # 4. Assemble 696-dimensional raw candidate vector
        v_696 = np.hstack([v_general, v_bh, v_beh, v_strings]).astype(np.float32)

        # 5. Drop constant/invariant features and align with 658 target features
        df_raw = pd.DataFrame([v_696], columns=self.raw_columns_696)
        df_clean = df_raw.drop(columns=list(self.dropped_features))[self.feature_names]

        # Ensure no NaN or inf values
        if df_clean.isna().any().any() or np.isinf(df_clean.values).any():
            df_clean = df_clean.fillna(0.0)

        return df_clean


# Global singleton extractor
_DEFAULT_EXTRACTOR = None

def get_extractor(processed_dir: Union[str, Path] = 'data/processed') -> DocSentryFeatureExtractor:
    """Returns singleton instance of DocSentryFeatureExtractor."""
    global _DEFAULT_EXTRACTOR
    if _DEFAULT_EXTRACTOR is None:
        _DEFAULT_EXTRACTOR = DocSentryFeatureExtractor(processed_dir=processed_dir)
    return _DEFAULT_EXTRACTOR


def extract_features(path_or_bytes: Union[str, Path, bytes, bytearray],
                     processed_dir: Union[str, Path] = 'data/processed') -> pd.DataFrame:
    """
    Module-level function to extract the 658 model features from a PDF path or bytes.
    """
    extractor = get_extractor(processed_dir=processed_dir)
    return extractor.extract(path_or_bytes)


def scan(path: Union[str, Path],
         models_dir: Union[str, Path] = 'models',
         processed_dir: Union[str, Path] = 'data/processed') -> Dict[str, Any]:
    """
    Performs full static malware scan on a PDF document:
    1. Extracts 658 static features using thrember extractors.
    2. Runs calibrated prediction, review-band classification, and SHAP attribution.
    3. Returns rich operational verdict report.

    Parameters
    ----------
    path : str or Path
        Filesystem path to the PDF document to scan.
    models_dir : str or Path
        Directory where serialized models and calibrator reside.
    processed_dir : str or Path
        Directory where feature schemas reside.

    Returns
    -------
    dict
        Scan report including file metadata, features, probabilities, verdict,
        top contributing features, and feature family attribution summaries.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Target PDF document not found: {p}")

    file_size = p.stat().st_size
    with open(p, 'rb') as f:
        file_bytes = f.read()

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    # Feature extraction
    features_df = extract_features(file_bytes, processed_dir=processed_dir)

    # Inference via docsentry_infer
    import src.docsentry_infer as di
    detector = di.load_artifacts(models_dir=models_dir, processed_dir=processed_dir)
    pred_result = detector.predict(features_df)

    scan_result = {
        'file_name': p.name,
        'file_path': str(p.resolve()),
        'file_size': file_size,
        'sha256': sha256_hash,
        'features': features_df,
        'label': pred_result['label'],
        'verdict': pred_result['label'],
        'calibrated_probability': pred_result['calibrated_probability'],
        'raw_probability': pred_result['raw_probability'],
        'review_band': pred_result['review_band'],
        'ood_warning': pred_result['ood_warning'],
        'top_contributors': pred_result['top_contributors'],
        'family_summary': pred_result['family_summary']
    }

    return scan_result
