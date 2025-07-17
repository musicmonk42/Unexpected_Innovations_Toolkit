# upm/ai_predictor.py

import os
import sys
import joblib
import numpy as np
import pandas as pd
import requests
import time
import json
import hashlib
from typing import Dict, Any, Optional, List

# Removed the self-referential import that was causing the circular dependency
# from upm.ai_predictor import AIRiskAssessor # THIS LINE WAS THE PROBLEM

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
    _TENACITY_AVAILABLE = True
except ImportError:
    # Fallback for tenacity not installed
    def retry(stop=None, wait=None, retry=None):
        def decorator(func):
            return func
        return decorator
    sys.stderr.write("Warning: 'tenacity' not installed. API requests will not have automatic retry logic.\n")

# Conditional import for shap for explainability
try:
    import shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False
    sys.stderr.write("Warning: 'shap' not installed. AI prediction explanations will be disabled.\n")


from upm.logging_utils import AUDIT_LOGGER, redact_secrets


def _is_retryable_http_error(exception: Exception) -> bool:
    """Return True if the exception is a retryable HTTP error (e.g., connection error or rate limit)."""
    if isinstance(exception, requests.exceptions.RequestException):
        if hasattr(exception, 'response') and exception.response is not None:
            # Retry on server-side errors and rate limiting
            return exception.response.status_code in [429, 500, 502, 503, 504]
        # Retry on connection errors, timeouts, etc.
        return True
    return False


class AIRiskAssessor:
    """
    Predicts the likelihood of a package being vulnerable based on metadata features.
    This version integrates real-world data fetching, robust feature handling, explainability,
    and resilience through caching and API retries.
    """
    def __init__(self, model_path: str = "upm_vuln_predictor_model.joblib", cache_dir: str = ".upm_cache/ai", verbose: bool = False):
        """
        Initializes the AIRiskAssessor.

        Args:
            model_path (str): The file path to save/load the trained ML model.
            cache_dir (str): Directory to store cached API responses.
            verbose (bool): If True, print detailed output during operations.
        """
        self.model_path = model_path
        self.cache_dir = cache_dir
        self.verbose = verbose
        self.model: Optional[RandomForestClassifier] = None
        self.imputer: Optional[SimpleImputer] = None
        self.feature_names: List[str] = []
        self.headers = {'User-Agent': 'UPM-AI-Predictor/1.1'}

        os.makedirs(self.cache_dir, exist_ok=True)
        self._load_model()

    def _load_model(self):
        """Loads a pre-trained model, imputer, and feature names from disk."""
        if os.path.exists(self.model_path):
            try:
                loaded_data = joblib.load(self.model_path)
                self.model = loaded_data['model']
                self.imputer = loaded_data['imputer']
                self.feature_names = loaded_data['feature_names']
                AUDIT_LOGGER.info(f"AIRiskAssessor: Loaded model from {self.model_path}")
                if self.verbose: print(f"AIRiskAssessor: Loaded model from {self.model_path}")
            except Exception as e:
                AUDIT_LOGGER.error(f"AIRiskAssessor: Failed to load model from {self.model_path}: {e}", exc_info=True)
                self.model = None
        else:
            if self.verbose: print(f"AIRiskAssessor: No model found at {self.model_path}. Model needs training.")

    def _save_model(self):
        """Saves the trained model, imputer, and feature names to disk."""
        if self.model and self.imputer and self.feature_names:
            try:
                model_data = {
                    'model': self.model,
                    'imputer': self.imputer,
                    'feature_names': self.feature_names
                }
                joblib.dump(model_data, self.model_path)
                AUDIT_LOGGER.info(f"AIRiskAssessor: Model saved to {self.model_path}")
                if self.verbose: print(f"AIRiskAssessor: Model saved to {self.model_path}")
            except Exception as e:
                AUDIT_LOGGER.error(f"AIRiskAssessor: Failed to save model to {self.model_path}: {e}", exc_info=True)

    def _generate_cache_key(self, package_list: List[Dict[str, str]]) -> str:
        """Creates a stable hash for a list of packages to use as a cache key."""
        sorted_list = sorted(package_list, key=lambda p: (p['type'], p['name'], p['version']))
        serialized = json.dumps(sorted_list, sort_keys=True).encode('utf-8')
        return hashlib.sha256(serialized).hexdigest()

    def fetch_training_data_from_oss_index(self, package_list: List[Dict[str, str]], cache_ttl_seconds: int = 86400) -> pd.DataFrame:
        """
        Fetches vulnerability data from OSS Index with caching, batching, and retry logic.
        """
        cache_key = self._generate_cache_key(package_list)
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")

        if os.path.exists(cache_path) and (time.time() - os.path.getmtime(cache_path)) < cache_ttl_seconds:
            if self.verbose: print("Fetching training data from local cache.")
            return pd.read_json(cache_path)

        if self.verbose: print(f"Fetching training data for {len(package_list)} packages from OSS Index API...")
        
        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=10), retry=retry_if_exception(_is_retryable_http_error))
        def _make_api_call(purls_batch):
            response = requests.post("https://ossindex.sonatype.org/api/v3/component-report", json={"coordinates": purls_batch}, timeout=60, headers=self.headers)
            response.raise_for_status()
            return response.json()

        all_api_data = []
        batch_size = 128 # OSS Index API supports up to 128 coordinates per request
        purls = [f"pkg:{pkg['type']}/{pkg.get('namespace', '')}/{pkg['name']}@{pkg['version']}".replace('//', '/') for pkg in package_list]

        for i in range(0, len(purls), batch_size):
            batch = purls[i:i + batch_size]
            if self.verbose: print(f"  - Fetching batch {i//batch_size + 1}...")
            try:
                all_api_data.extend(_make_api_call(batch))
            except Exception as e:
                AUDIT_LOGGER.error(f"AIRiskAssessor: Could not fetch data from OSS Index API after multiple retries: {e}")
                if os.path.exists(cache_path):
                    if self.verbose: print("API fetch failed. Falling back to stale cache.")
                    return pd.read_json(cache_path)
                return pd.DataFrame()
        
        # Simulate richer features as this API only provides vulnerability data
        records = [
            {
                'dependency_age_days': pkg.get('age_days', np.random.randint(50, 2000)),
                'num_known_cves_past_year': len(report.get("vulnerabilities", [])),
                'maintainer_activity_score': pkg.get('activity', np.random.rand() * 10),
                'transitive_dependency_count': pkg.get('deps', np.random.randint(0, 30)),
                'has_install_scripts': int(pkg.get('has_scripts', False)),
                'license_is_permissive': int(pkg.get('permissive_license', True)),
                'is_vulnerable': 1 if report.get("vulnerabilities") else 0
            }
            for pkg, report in zip(package_list, all_api_data)
        ]
        
        df = pd.DataFrame(records)
        df.to_json(cache_path)
        return df

    def train_model(self, data: Optional[pd.DataFrame] = None):
        """Trains and evaluates a new vulnerability prediction model."""
        if data is None:
            sample_packages = [
                {'type': 'pypi', 'name': 'requests', 'version': '2.28.1'}, {'type': 'npm', 'name': 'express', 'version': '4.18.2'},
                {'type': 'pypi', 'name': 'django', 'version': '3.2'}, {'type': 'npm', 'name': 'lodash', 'version': '4.17.20'},
                {'type': 'pypi', 'name': 'pillow', 'version': '9.0.0'},
            ]
            data = self.fetch_training_data_from_oss_index(sample_packages)

        if data.empty:
            AUDIT_LOGGER.error("AIRiskAssessor: Training data is empty. Aborting training.")
            return

        self.feature_names = [col for col in data.columns if col != 'is_vulnerable']
        X = data[self.feature_names]
        y = data['is_vulnerable']

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
        
        self.imputer = SimpleImputer(strategy='median')
        X_train_imputed = self.imputer.fit_transform(X_train)
        X_test_imputed = self.imputer.transform(X_test)

        self.model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        if self.verbose: print("AIRiskAssessor: Training model...")
        self.model.fit(X_train_imputed, y_train)

        y_pred_proba = self.model.predict_proba(X_test_imputed)[:, 1]
        accuracy = accuracy_score(y_test, self.model.predict(X_test_imputed))
        roc_auc = roc_auc_score(y_test, y_pred_proba) if len(np.unique(y_test)) > 1 else float('nan')
        
        AUDIT_LOGGER.info(f"AIRiskAssessor: Model training complete.", extra={"accuracy": f"{accuracy:.4f}", "roc_auc": f"{roc_auc:.4f}"})
        if self.verbose: print(f"AIRiskAssessor: Model Evaluation - Accuracy: {accuracy:.4f}, ROC AUC: {roc_auc:.4f}")
        
        self._save_model()

    def predict_likelihood(self, package_features: Dict[str, Any]) -> float:
        """Predicts vulnerability likelihood after robustly handling missing features."""
        if not all([self.model, self.imputer, self.feature_names]):
            AUDIT_LOGGER.warning("AIRiskAssessor: Model not loaded. Returning default risk 0.0.")
            return 0.0
        
        # Ensure package_features is a dictionary before creating DataFrame
        if not isinstance(package_features, dict):
            AUDIT_LOGGER.error("AIRiskAssessor: Invalid input for prediction. Expected a dictionary of features.")
            return 0.0

        try:
            features_df = pd.DataFrame([package_features], columns=self.feature_names)
        except Exception as e:
            AUDIT_LOGGER.error(f"AIRiskAssessor: Failed to create DataFrame from package features: {e}", exc_info=True)
            return 0.0
        
        try:
            features_imputed = self.imputer.transform(features_df)
            likelihood = self.model.predict_proba(features_imputed)[0, 1]
            AUDIT_LOGGER.info(
                "Vulnerability prediction performed.",
                extra={"input": redact_secrets(str(package_features)), "output": float(likelihood)}
            )
            if self.verbose: print(f"AIRiskAssessor: Predicted likelihood: {likelihood:.4f}")
            return likelihood
        except Exception as e:
            AUDIT_LOGGER.error("AIRiskAssessor: Error during prediction.", extra={"input": redact_secrets(str(package_features)), "error": str(e)}, exc_info=True)
            return 0.0

    def explain_prediction(self, package_features: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Provides feature contributions to a prediction using SHAP, if available."""
        if not _SHAP_AVAILABLE:
            if self.verbose: print("SHAP library not installed. Cannot generate explanation.")
            return None
        if not all([self.model, self.imputer, self.feature_names]):
            AUDIT_LOGGER.warning("AIRiskAssessor: Model not loaded. Cannot generate explanation.")
            return None

        features_df = pd.DataFrame([package_features], columns=self.feature_names)
        features_imputed = self.imputer.transform(features_df)
        
        explainer = shap.TreeExplainer(self.model)
        shap_values = explainer.shap_values(features_imputed)
        
        feature_impact = dict(zip(self.feature_names, shap_values[1][0]))
        
        if self.verbose:
            print("\n--- Prediction Explanation (SHAP Feature Impact) ---")
            for feature, impact in sorted(feature_impact.items(), key=lambda item: abs(item[1]), reverse=True):
                print(f"  - {feature:<28}: {impact:+.4f} {'(increases risk)' if impact > 0 else '(decreases risk)'}")
            print("-------------------------------------------------")
            
        return feature_impact

# --- Self-validation / Example Usage ---
if __name__ == "__main__":
    import tempfile
    import logging

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    with tempfile.TemporaryDirectory() as tmpdir:
        model_file_path = os.path.join(tmpdir, "prod_model.joblib")
        cache_dir_path = os.path.join(tmpdir, "ai_cache")
        
        print(f"--- Using temporary directory for model and cache: {tmpdir} ---")

        print("\n[STEP 1] Training a new model with data from OSS Index...")
        predictor = AIRiskAssessor(model_path=model_file_path, cache_dir=cache_dir_path, verbose=True)
        predictor.train_model()
        assert predictor.model is not None, "Training failed"
        
        print("\n[STEP 2] Making a prediction on a potentially high-risk package...")
        high_risk_features = {
            'dependency_age_days': 2500,
            'num_known_cves_past_year': 4,
            'maintainer_activity_score': None,
            'transitive_dependency_count': 40,
            'has_install_scripts': 1,
            'license_is_permissive': 1
        }
        likelihood = predictor.predict_likelihood(high_risk_features)
        
        print(f"\n[STEP 3] Explaining the prediction for the high-risk package (requires 'shap' to be installed)...")
        predictor.explain_prediction(high_risk_features)
        
        print("\n--- Self-validation complete. ---")