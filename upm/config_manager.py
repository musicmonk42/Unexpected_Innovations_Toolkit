# upm/config_manager.py

import os
import yaml
import re
import json
import asyncio
from typing import Dict, Any, Optional, List

from upm.encryption import EncryptionManager
from upm.logging_utils import AUDIT_LOGGER

try:
    from pydantic import BaseModel, Field, ValidationError
    _PYDANTIC_AVAILABLE = True
except ImportError:
    BaseModel, Field, ValidationError = object, object, None
    _PYDANTIC_AVAILABLE = False

SENSITIVE_KEYS_ENV_MAP = {"api_key": "UPM_API_KEY", "email_password": "UPM_EMAIL_PASSWORD", "slack_token": "UPM_SLACK_TOKEN"}
SECRET_NAME_PATTERN = re.compile(r'key|token|password|secret', re.IGNORECASE)

if _PYDANTIC_AVAILABLE:
    class PolicyModel(BaseModel):
        blocked_packages: List[str] = Field(default_factory=list)
        allowed_packages: Optional[Dict[str, List[str]]] = None
        pinned_versions: Dict[str, Dict[str, str]] = Field(default_factory=dict)

class UPMConfig:
    def __init__(self, project_root: str, verbose: bool = False, error_tracker: Any = None, **kwargs):
        self.project_root = project_root
        self.config_path = os.path.join(project_root, kwargs.get("config_path", ".unipkgrc"))
        self.policy_path = os.path.join(project_root, kwargs.get("policy_path", ".unipkgpolicy.yaml"))
        self.verbose = verbose
        self.error_tracker = error_tracker
        self.config: Dict[str, Any] = {}
        self.policy: Dict[str, Any] = {}

    @classmethod
    async def create(cls, project_root: str, **kwargs):
        instance = cls(project_root, **kwargs)
        await instance.load_config()
        await instance.load_policy()
        return instance

    def _resolve_secrets_from_env(self, config_data: Dict[str, Any]):
        for key, value in config_data.items():
            if isinstance(value, dict):
                self._resolve_secrets_from_env(value)
            elif (env_var := SENSITIVE_KEYS_ENV_MAP.get(key)) and (env_value := os.getenv(env_var)):
                config_data[key] = env_value

    async def load_config(self) -> None:
        if not os.path.exists(self.config_path):
            self.config = {}
            return
        
        try:
            with open(self.config_path, 'rb') as f:
                raw_content = await asyncio.to_thread(f.read)
            loaded_config = yaml.safe_load(raw_content) or {}
        except Exception as e:
            if self.error_tracker: self.error_tracker.add_error(f"Failed to load config: {e}")
            loaded_config = {}
        
        self._resolve_secrets_from_env(loaded_config)
        self.config = loaded_config

    async def load_policy(self) -> None:
        if not os.path.exists(self.policy_path):
            self.policy = {}
            return

        try:
            with open(self.policy_path, 'r', encoding="utf-8") as f:
                policy_data = await asyncio.to_thread(yaml.safe_load, f) or {}
        except Exception as e:
            if self.error_tracker: self.error_tracker.add_error(f"Failed to load policy file: {e}")
            policy_data = {}
        
        if _PYDANTIC_AVAILABLE and PolicyModel:
            try:
                validated_model = PolicyModel.model_validate(policy_data)
                self.policy = validated_model.model_dump()
            except ValidationError as e:
                if self.error_tracker: self.error_tracker.add_error(f"Policy validation error: {e}")
                self.policy = PolicyModel().model_dump()
        else:
            self.policy = policy_data

    def get_config(self) -> Dict[str, Any]:
        return self.config

    def get_policy(self) -> Dict[str, Any]:
        return self.policy