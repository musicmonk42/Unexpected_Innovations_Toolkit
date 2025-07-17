# tests/test_ai_predictor.py

import pytest
import os
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from pathlib import Path
import logging # For caplog
import time 

from upm.ai_predictor import AIRiskAssessor
from upm.logging_utils import AUDIT_LOGGER, flush_logs

# Import libraries that will be aggressively mocked
import joblib
import pandas as pd
import sklearn.ensemble
import sklearn.impute
import requests
import sys 
import numpy as np

# --- Fixtures ---

@pytest.fixture
def temp_model_dir(tmp_path):
    """Provides a temporary directory for mock model files."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "upm_vuln_predictor_model.joblib").write_bytes(b"dummy model data")
    return str(model_dir)

@pytest.fixture(autouse=True, scope="module") 
def aggressive_mock_scientific_libs():
    with patch('joblib.load') as mock_joblib_load, \
         patch('joblib.dump') as mock_joblib_dump, \
         patch('pandas.DataFrame') as mock_pd_dataframe, \
         patch('pandas.read_json') as mock_pd_read_json, \
         patch('sklearn.ensemble.RandomForestClassifier') as mock_rf_classifier, \
         patch('sklearn.impute.SimpleImputer') as mock_simple_imputer, \
         patch('sklearn.model_selection.train_test_split') as mock_train_test_split, \
         patch('sklearn.metrics.roc_auc_score') as mock_roc_auc_score, \
         patch('sklearn.metrics.accuracy_score') as mock_accuracy_score, \
         patch('requests.post') as mock_requests_post, \
         patch('requests.exceptions.RequestException') as mock_requests_exception, \
         patch('numpy.random.randint') as mock_np_randint:
        
        mock_model_instance = MagicMock()
        mock_model_instance.predict_proba.return_value = np.array([[0.25, 0.75]])
        mock_imputer_instance = MagicMock()
        mock_imputer_instance.transform.return_value = MagicMock(name="imputer_transform_result")

        mock_joblib_load.return_value = {
            'model': mock_model_instance,
            'imputer': mock_imputer_instance,
            'feature_names': ['dependency_age_days', 'num_known_cves_past_year', 'maintainer_activity_score', 'transitive_dependency_count', 'has_install_scripts', 'license_is_permissive']
        }

        mock_pd_dataframe.return_value = MagicMock(name="dataframe_instance")
        mock_pd_read_json.return_value = MagicMock(name="read_json_dataframe")
        mock_rf_classifier.return_value = mock_model_instance
        mock_simple_imputer.return_value = mock_imputer_instance
        mock_train_test_split.return_value = (MagicMock(), MagicMock(), MagicMock(), MagicMock())
        mock_roc_auc_score.return_value = 0.95
        mock_accuracy_score.return_value = 0.9
        
        mock_response = MagicMock(status_code=200)
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = [{"vulnerabilities": []}]
        mock_requests_post.return_value.__enter__.return_value = mock_response

        mock_np_randint.return_value = 100

        yield mock_joblib_load, mock_joblib_dump

@pytest.fixture(autouse=True)
def mock_filesystem_operations():
    with patch('os.makedirs') as mock_makedirs, \
         patch('os.path.exists') as mock_exists:
        mock_exists.return_value = True
        yield mock_makedirs, mock_exists

@pytest.fixture
def ai_predictor_instance(temp_model_dir):
    return AIRiskAssessor(
        model_path=os.path.join(temp_model_dir, "upm_vuln_predictor_model.joblib"),
        cache_dir=os.path.join(temp_model_dir, ".upm_cache", "ai"),
        verbose=False
    )

# --- Tests for Initialization ---

def test_init_success(ai_predictor_instance, aggressive_mock_scientific_libs):
    mock_load, _ = aggressive_mock_scientific_libs
    assert ai_predictor_instance.model is not None
    mock_load.assert_called_once_with(ai_predictor_instance.model_path)

def test_init_model_not_found(temp_model_dir, aggressive_mock_scientific_libs, mock_filesystem_operations, caplog):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_makedirs, mock_exists = mock_filesystem_operations
    mock_exists.side_effect = lambda path: False if path == os.path.join(temp_model_dir, "non_existent_model.joblib") else True
    mock_load.reset_mock()
    with caplog.at_level(logging.DEBUG, logger="unipkg_audit"):
        predictor = AIRiskAssessor(
            model_path=os.path.join(temp_model_dir, "non_existent_model.joblib"),
            cache_dir=os.path.join(temp_model_dir, ".upm_cache", "ai"),
            verbose=False
        )
    assert predictor.model is None
    mock_load.assert_not_called()
    mock_makedirs.assert_called_once()
    mock_exists.assert_any_call(predictor.model_path)

def test_init_disabled(temp_model_dir, aggressive_mock_scientific_libs, mock_filesystem_operations, caplog):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_makedirs, mock_exists = mock_filesystem_operations
    mock_exists.side_effect = lambda path: False if path == os.path.join(temp_model_dir, "non_existent_model.joblib") else True
    mock_load.reset_mock()
    with caplog.at_level(logging.DEBUG, logger="unipkg_audit"):
        predictor = AIRiskAssessor(
            model_path=os.path.join(temp_model_dir, "non_existent_model.joblib"),
            cache_dir=os.path.join(temp_model_dir, ".upm_cache", "ai"),
            verbose=False
        )
    assert predictor.model is None
    mock_load.assert_not_called()
    mock_makedirs.assert_called_once()
    mock_exists.assert_any_call(predictor.model_path)

# --- Tests for Prediction Functionality ---

@pytest.mark.asyncio
async def test_predict_risk_success(ai_predictor_instance, aggressive_mock_scientific_libs):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_model = mock_load.return_value['model']
    mock_model.predict_proba.side_effect = None
    mock_model.predict_proba.return_value = np.array([[0.25, 0.75]])
    package_data = {'dependency_age_days': 100, 'num_known_cves_past_year': 0, 'maintainer_activity_score': 5.0, 'transitive_dependency_count': 10, 'has_install_scripts': 0, 'license_is_permissive': 1}
    risk_score = ai_predictor_instance.predict_likelihood(package_data)
    assert risk_score == 0.75
    mock_model.predict_proba.assert_called_once()

@pytest.mark.asyncio
async def test_predict_risk_disabled_returns_default(temp_model_dir, aggressive_mock_scientific_libs, mock_filesystem_operations, caplog):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_makedirs, mock_exists = mock_filesystem_operations
    mock_exists.side_effect = lambda path: False if path == os.path.join(temp_model_dir, "non_existent_model.joblib") else True
    mock_load.reset_mock()
    AUDIT_LOGGER.propagate = True
    with caplog.at_level(logging.WARNING):
        predictor = AIRiskAssessor(model_path=os.path.join(temp_model_dir, "non_existent_model.joblib"), cache_dir=os.path.join(temp_model_dir, ".upm_cache", "ai"), verbose=False)
        package_data = {'dependency_age_days': 100, 'num_known_cves_past_year': 0, 'maintainer_activity_score': 5.0, 'transitive_dependency_count': 10, 'has_install_scripts': 0, 'license_is_permissive': 1}
        risk_score = predictor.predict_likelihood(package_data)
        flush_logs()
    AUDIT_LOGGER.propagate = False
    mock_makedirs.assert_called_once()
    mock_exists.assert_any_call(predictor.model_path)
    assert risk_score == 0.0
    assert "AIRiskAssessor: Model not loaded. Returning default risk 0.0." in caplog.text
    mock_load.assert_not_called()

@pytest.mark.asyncio
async def test_predict_risk_model_error(ai_predictor_instance, aggressive_mock_scientific_libs, caplog):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_model = mock_load.return_value['model']
    mock_model.predict_proba.side_effect = ValueError("Model inference failed")
    package_data = {'dependency_age_days': 100, 'num_known_cves_past_year': 0, 'maintainer_activity_score': 5.0, 'transitive_dependency_count': 10, 'has_install_scripts': 0, 'license_is_permissive': 1}
    AUDIT_LOGGER.propagate = True
    with caplog.at_level(logging.ERROR):
        risk_score = ai_predictor_instance.predict_likelihood(package_data)
        flush_logs()
    AUDIT_LOGGER.propagate = False
    assert risk_score == 0.0
    assert "AIRiskAssessor: Error during prediction." in caplog.text

# --- Tests for Integration and Edge Cases ---

@pytest.mark.asyncio
async def test_predict_risk_with_realistic_features(ai_predictor_instance, aggressive_mock_scientific_libs):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_model = mock_load.return_value['model']
    mock_model.predict_proba.side_effect = None
    mock_model.predict_proba.return_value = np.array([[0.1, 0.9]])
    package_data = {'dependency_age_days': 2500, 'num_known_cves_past_year': 4, 'maintainer_activity_score': 1.5, 'transitive_dependency_count': 40, 'has_install_scripts': 1, 'license_is_permissive': 0}
    risk_score = ai_predictor_instance.predict_likelihood(package_data)
    assert risk_score == 0.9

@pytest.mark.asyncio
async def test_predict_risk_concurrency(ai_predictor_instance, aggressive_mock_scientific_libs):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_model = mock_load.return_value['model']
    mock_model.predict_proba.reset_mock()
    mock_model.predict_proba.side_effect = None
    mock_model.predict_proba.return_value = np.array([[0.25, 0.75]])
    package_data = {'dependency_age_days': 100, 'num_known_cves_past_year': 0, 'maintainer_activity_score': 5.0, 'transitive_dependency_count': 10, 'has_install_scripts': 0, 'license_is_permissive': 1}
    tasks = [asyncio.to_thread(ai_predictor_instance.predict_likelihood, package_data) for _ in range(10)]
    results = await asyncio.gather(*tasks)
    assert all(score == 0.75 for score in results)
    assert mock_model.predict_proba.call_count == 10

# --- Tests for Logging and Metrics ---

def test_predict_risk_logs(ai_predictor_instance, aggressive_mock_scientific_libs, caplog):
    mock_load, _ = aggressive_mock_scientific_libs
    mock_model = mock_load.return_value['model']
    mock_model.predict_proba.side_effect = None
    mock_model.predict_proba.return_value = np.array([[0.25, 0.75]])
    package_data = {'dependency_age_days': 100, 'num_known_cves_past_year': 0, 'maintainer_activity_score': 5.0, 'transitive_dependency_count': 10, 'has_install_scripts': 0, 'license_is_permissive': 1}
    AUDIT_LOGGER.propagate = True
    with caplog.at_level(logging.INFO):
        ai_predictor_instance.predict_likelihood(package_data)
        flush_logs()
    AUDIT_LOGGER.propagate = False
    assert "Vulnerability prediction performed." in caplog.text

# --- Error Handling and Fuzzing ---

@pytest.mark.parametrize("invalid_data", [
    {"non_existent_feature": 123},
    {"dependency_age_days": "not_a_number"},
    None
])
@pytest.mark.asyncio
async def test_predict_risk_invalid_input(ai_predictor_instance, aggressive_mock_scientific_libs, invalid_data, caplog):
    if invalid_data is None:
        risk_score = ai_predictor_instance.predict_likelihood(invalid_data)
        assert risk_score == 0.0
        return
    mock_imputer = ai_predictor_instance.imputer
    mock_imputer.transform.side_effect = ValueError("Invalid data type for imputation")
    AUDIT_LOGGER.propagate = True
    with caplog.at_level(logging.ERROR):
        risk_score = ai_predictor_instance.predict_likelihood(invalid_data)
        flush_logs()
    AUDIT_LOGGER.propagate = False
    assert risk_score == 0.0
    assert "AIRiskAssessor: Error during prediction." in caplog.text
    mock_imputer.transform.side_effect = None