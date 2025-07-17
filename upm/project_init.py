# upm/project_init.py

import os
import yaml
import json
import toml
import re
import shutil
import subprocess
import logging
from typing import Dict, List, Any, Optional, Tuple, Callable
from upm.logging_utils import AUDIT_LOGGER, get_current_user, log_audit, AuditOperation

# --- Custom Exception ---
class ProjectInitializationError(Exception):
    """Custom exception for errors during project initialization."""
    pass

# --- Constants ---
TEMPLATE_DIR_NAME = "upm_templates"
VALID_PROJECT_NAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]+$")

# --- Helper Functions ---

def _serialize_content(filename: str, content: Any) -> str:
    """Serializes structured data to the appropriate format based on file extension."""
    if filename.endswith(".json"):
        return json.dumps(content, indent=2)
    elif filename.endswith((".yaml", ".yml")):
        return yaml.dump(content, default_flow_style=False)
    elif filename.endswith(".toml"):
        if isinstance(content, dict):
            return toml.dumps(content)
        else:
            raise TypeError(f"TOML content for '{filename}' must be a dictionary.")
    return str(content)

# --- Project Initialization for Universal Package Manager (UPM) ---

class ProjectInitializer:
    """
    Manages the initialization of new projects from templates.

    Implements security measures including path validation, overwrite protection,
    and atomic creation with rollback capabilities to ensure safe project scaffolding.
    """

    def __init__(self, base_dir: str = "."):
        """
        Initializes the project creator.

        Args:
            base_dir (str): The base directory where templates are located and projects are created.
        """
        self.base_dir = os.path.abspath(base_dir)
        self.template_path = os.path.join(self.base_dir, TEMPLATE_DIR_NAME)
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, Dict[str, Any]]:
        """
        Discovers and loads all valid project templates from the 'upm_templates' directory.
        """
        loaded_templates = {}
        if not os.path.isdir(self.template_path):
            AUDIT_LOGGER.info(f"Template directory '{TEMPLATE_DIR_NAME}' not found. No templates loaded.")
            return loaded_templates

        for filename in os.listdir(self.template_path):
            if filename.endswith((".yaml", ".yml")):
                template_name = os.path.splitext(filename)[0]
                filepath = os.path.join(self.template_path, filename)
                try:
                    with open(filepath, 'r') as f:
                        template_data = yaml.safe_load(f)
                        if isinstance(template_data, dict) and 'files' in template_data:
                            loaded_templates[template_name] = template_data
                            AUDIT_LOGGER.debug(f"Successfully loaded template '{template_name}'.")
                        else:
                            AUDIT_LOGGER.warning(f"Skipping invalid template file '{filename}': Must be a dictionary containing a 'files' key.")
                except (yaml.YAMLError, IOError) as e:
                    AUDIT_LOGGER.error(f"Failed to load template '{filename}': {e}", exc_info=True)
        return loaded_templates

    def list_templates(self) -> List[Tuple[str, str]]:
        """Returns a list of available templates and their versions."""
        if not self.templates:
            return []
        return [
            (name, template.get("version", "N/A"))
            for name, template in self.templates.items()
        ]

    def _rollback_creation(self, paths: List[str]) -> None:
        """
        Rolls back the project creation by deleting all created files and directories.

        Args:
            paths (List[str]): A list of absolute paths to files/directories that were created.
        """
        log_audit(logging.WARNING, "Project creation failed. Rolling back changes.", operation=AuditOperation.PROJECT_INIT)
        paths.sort(key=len, reverse=True)
        for path in paths:
            try:
                if os.path.isfile(path):
                    os.remove(path)
                    AUDIT_LOGGER.debug(f"Rollback: Removed file '{path}'.")
                elif os.path.isdir(path):
                    if not os.listdir(path):
                         os.rmdir(path)
                    else:
                         shutil.rmtree(path)
                    AUDIT_LOGGER.debug(f"Rollback: Removed directory '{path}'.")
            except OSError as e:
                AUDIT_LOGGER.error(f"Rollback failed to remove '{path}': {e}", exc_info=True)

    def create_project(
        self,
        project_name: str,
        template_name: str,
        author: Optional[str] = None,
        force: bool = False,
        init_git: bool = False
    ) -> bool:
        """
        Creates a new project directory from a specified template.
        """
        if not VALID_PROJECT_NAME_REGEX.match(project_name):
            raise ProjectInitializationError(f"Invalid project name '{project_name}'. It contains illegal characters.")

        if template_name not in self.templates:
            raise ProjectInitializationError(f"Template '{template_name}' not found.")

        author_name = author or get_current_user()
        template = self.templates[template_name]
        files_to_create = template.get("files", {})

        project_root = os.path.abspath(os.path.join(self.base_dir, project_name))
        created_paths = []

        try:
            # FIX: Replace the simple non-empty check with a more nuanced one that allows for file-level overwrites.
            if os.path.exists(project_root) and not force:
                # Check for existing files that are NOT part of the template. If such files exist, it's an error.
                template_filenames = set(files_to_create.keys())
                for dirpath, _, filenames in os.walk(project_root):
                    for f in filenames:
                        # Get the relative path of the existing file to compare with template keys
                        relative_path = os.path.relpath(os.path.join(dirpath, f), project_root).replace('\\', '/')
                        if relative_path not in template_filenames:
                            raise ProjectInitializationError(f"Directory '{project_root}' already exists and contains unmanaged files (e.g., '{relative_path}'). Use --force to overwrite.")

            if os.path.exists(project_root) and force:
                shutil.rmtree(project_root)

            os.makedirs(project_root, exist_ok=True)
            created_paths.append(project_root)
            log_audit(logging.INFO, f"Creating project '{project_name}' from template '{template_name}'.", operation=AuditOperation.PROJECT_INIT)

            for filename, content in files_to_create.items():
                output_path = os.path.abspath(os.path.join(project_root, filename))

                if not output_path.startswith(os.path.realpath(project_root)):
                    raise ProjectInitializationError(f"Security violation: path {output_path} is outside the project root {project_root}")
                if os.path.islink(os.path.dirname(output_path)) and not os.path.realpath(os.path.dirname(output_path)).startswith(os.path.realpath(project_root)):
                    raise ProjectInitializationError(f"Security violation: attempted to write through a symlink to an external path")

                if os.path.exists(output_path) and not force:
                    if input(f"File '{filename}' already exists. Overwrite? (y/N): ").lower() != 'y':
                        AUDIT_LOGGER.info(f"Skipping existing file '{filename}'.")
                        continue

                if isinstance(content, str):
                    final_content = content.format(project_name=project_name, author=author_name)
                else:
                    def format_recursive(item):
                        if isinstance(item, str): return item.format(project_name=project_name, author=author_name)
                        elif isinstance(item, dict): return {k: format_recursive(v) for k, v in item.items()}
                        elif isinstance(item, list): return [format_recursive(i) for i in item]
                        return item
                    final_content = _serialize_content(filename, format_recursive(content))

                parent_dir = os.path.dirname(output_path)
                os.makedirs(parent_dir, exist_ok=True)
                created_paths.append(output_path)

                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(final_content)
                AUDIT_LOGGER.debug(f"Created file '{output_path}'.")

            if init_git:
                try:
                    subprocess.run(["git", "init"], cwd=project_root, check=True, capture_output=True, text=True)
                    log_audit(logging.INFO, "Initialized Git repository.", operation=AuditOperation.PROJECT_INIT, context={"project": project_name})
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    AUDIT_LOGGER.warning(f"Failed to initialize Git repository: {e}")
                    raise ProjectInitializationError(f"Git initialization failed: {e}") from e

            log_audit(logging.INFO, f"Project '{project_name}' created successfully.", operation=AuditOperation.PROJECT_INIT)
            return True

        except Exception as e:
            self._rollback_creation(created_paths)
            if isinstance(e, ProjectInitializationError):
                raise
            raise ProjectInitializationError(f"An error occurred during project creation: {e}") from e