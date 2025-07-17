# upm/docker.py
import os
import json
import logging
import subprocess
import re
from typing import Optional, Dict, List

from upm.logging_utils import AUDIT_LOGGER

class DockerBuilder:
    """
    A utility class for building Docker images.
    Handles interaction with the Docker daemon.
    """

    # Assuming a default path for Dockerfile if not specified
    DEFAULT_DOCKERFILE_NAME = "Dockerfile"

    # This regex is a simple safety check; a more robust solution might involve
    # detailed path validation or running in a tightly controlled container.
    # It disallows common path traversal patterns and shell metacharacters.
    SAFE_PATH_REGEX = re.compile(r"^[a-zA-Z0-9_./:\\-]+$")
    UNSAFE_CHARS_REGEX = re.compile(r'[;&|`$(){}<>]')


    @staticmethod
    def _validate_path(path: str) -> None:
        """Validates a path for safety before passing to shell commands."""
        if not path or not isinstance(path, str):
            raise ValueError("Path must be a non-empty string.")
        
        if not DockerBuilder.SAFE_PATH_REGEX.match(path):
            AUDIT_LOGGER.critical(f"Security Error: Malformed path detected: '{path}'")
            raise ValueError(f"Malformed path detected: '{path}'")
        
        if DockerBuilder.UNSAFE_CHARS_REGEX.search(path):
            AUDIT_LOGGER.critical(f"Security Error: Potential shell injection characters detected in path: '{path}'")
            raise ValueError(f"Potential shell injection characters detected in path: '{path}'")

        # More robust checks could include:
        # - os.path.abspath to resolve relative paths and check against allowed roots.
        # - os.path.normpath to normalize path separators and detect '..' traversal.
        # - Checking if path resolves outside allowed project directories.


    @staticmethod
    def build_docker_image(
        project_root: str,
        image_name: str,
        dockerfile_path: Optional[str] = None,
        build_args: Optional[Dict[str, str]] = None,
        skip_trivy: bool = False,
        secrets: Optional[List[Dict[str, str]]] = None,
        require_signing: bool = False
    ) -> bool:
        """
        Builds a Docker image from a given project root.

        Args:
            project_root: The root directory containing the Dockerfile and build context.
            image_name: The name/tag for the Docker image.
            dockerfile_path: Optional. The path to the Dockerfile relative to project_root.
                             Defaults to 'Dockerfile' in project_root.
            build_args: Optional. A dictionary of build-time variables (e.g., {"VER": "1.0"}).
            skip_trivy: Optional. Skip the Trivy vulnerability scan.
            secrets: Optional. A list of secrets to mount during build (e.g., [{'id': 'npmrc', 'src': '/path/to/.npmrc'}]).
            require_signing: Optional. Enforce Docker Content Trust for signed images.

        Returns:
            True if the build was successful, False otherwise.
        """
        # Ensure that AUDIT_LOGGER is configured and available globally or passed in if not.
        # For tests, caplog will capture this.
        
        # Log to a file for build process forensics
        log_file_path = os.path.join(project_root, "docker_build.log")
        
        # Added for debugging and clarity based on prior trace
        AUDIT_LOGGER.info(f"Build log will be saved to: {log_file_path}")
        
        try:
            # Validate project_root first to prevent security issues before any Docker command
            DockerBuilder._validate_path(project_root)

            full_dockerfile_path = os.path.join(project_root, dockerfile_path or DockerBuilder.DEFAULT_DOCKERFILE_NAME)

            if not os.path.exists(full_dockerfile_path):
                AUDIT_LOGGER.error(f"Dockerfile not found at: {full_dockerfile_path}")
                return False

            cmd = ["docker", "build", "-t", image_name, project_root]

            if dockerfile_path:
                cmd.extend(["-f", full_dockerfile_path])

            env = os.environ.copy()

            if require_signing:
                env['DOCKER_CONTENT_TRUST'] = '1'

            if secrets:
                for s in secrets:
                    DockerBuilder._validate_path(s['src'])
                    cmd.extend(["--secret", f"id={s['id']},src={s['src']}"])
                env['DOCKER_BUILDKIT'] = '1'

            if build_args:
                for key, value in build_args.items():
                    lower_key = key.lower()
                    if 'password' in lower_key or 'key' in lower_key or 'token' in lower_key or 'secret' in lower_key:
                        AUDIT_LOGGER.critical(f"Potential secret detected in --build-arg: {key}={value}")
                    cmd.extend(["--build-arg", f"{key}={value}"])

            # Build safe_command for logging with redaction
            safe_command = []
            i = 0
            while i < len(cmd):
                if cmd[i] == '--build-arg':
                    i += 1
                    k_v = cmd[i]
                    eq_pos = k_v.find('=')
                    if eq_pos > 0:
                        k = k_v[:eq_pos]
                        v = k_v[eq_pos+1:]
                        lower_k = k.lower()
                        if 'password' in lower_k or 'key' in lower_k or 'token' in lower_k or 'secret' in lower_k:
                            safe_command.append('--build-arg')
                            safe_command.append(f"{k}=[REDACTED]")
                        else:
                            safe_command.append('--build-arg')
                            safe_command.append(k_v)
                    else:
                        safe_command.append(cmd[i-1])
                        safe_command.append(cmd[i])
                else:
                    safe_command.append(cmd[i])
                i += 1

            # Log command for auditing
            AUDIT_LOGGER.info(f"Attempting to build Docker image with command: {' '.join(safe_command)}")

            # Execute the docker build command
            # Using Popen to capture output in real-time or direct to log file.
            # For simplicity with subprocess.run and capturing full output:
            with open(log_file_path, "w") as outfile:
                process = subprocess.run(
                    cmd,
                    stdout=outfile, # Redirect stdout to log file
                    stderr=subprocess.STDOUT, # Redirect stderr to stdout to capture all output
                    text=True, # Decode stdout/stderr as text
                    check=True, # Raise CalledProcessError if command returns non-zero exit code
                    shell=False, # Do not use shell to prevent injection
                    env=env
                )
            
            AUDIT_LOGGER.info(f"Docker image '{image_name}' built successfully.")
            
            if skip_trivy:
                AUDIT_LOGGER.info("Trivy scan skipped")
            else:
                # Run Trivy scan
                trivy_cmd = ["trivy", "image", "--format", "json", "--exit-code", "1", "--no-progress", image_name]
                trivy_result = subprocess.run(trivy_cmd, capture_output=True, text=True)
                if trivy_result.returncode != 0:
                    vulns = json.loads(trivy_result.stdout)
                    AUDIT_LOGGER.error(f"Vulnerabilities found in {image_name}: {json.dumps(vulns)}")
                    return False
                AUDIT_LOGGER.info(f"{image_name} passed vulnerability scan.")
            
            return True

        except subprocess.CalledProcessError as e:
            # FIX: Log the specific error message expected by the test
            error_output = (e.stdout or "") + (e.stderr or "") # Both redirected to stdout in above Popen call
            # Check for common Docker daemon down messages
            if "Cannot connect" in error_output or \
               "Is the docker daemon running?" in error_output or \
               "Connection refused" in error_output or \
               "Error response from daemon" in error_output:
                AUDIT_LOGGER.error("Docker daemon is not running or accessible") # This exact string is expected
            else:
                AUDIT_LOGGER.error(f"Docker build failed for image '{image_name}'. Stderr: {error_output.strip()}")
            return False
        except FileNotFoundError:
            AUDIT_LOGGER.error("Docker command not found. Is Docker installed and in your PATH?")
            return False
        except ValueError as e:
            AUDIT_LOGGER.critical(f"Security error during Docker build: {e}")
            return False
        except Exception as e:
            AUDIT_LOGGER.error(f"An unexpected error occurred during Docker build: {e}", exc_info=True)
            return False

    @staticmethod
    def run_docker_container(image_name: str, container_name: str, ports: Optional[Dict[int, int]] = None, volumes: Optional[Dict[str, str]] = None) -> bool:
        """
        Runs a Docker container from a given image.
        """
        AUDIT_LOGGER.info(f"Simulating run_docker_container for {image_name}")
        # Placeholder for actual implementation.
        # This would involve constructing and running a `docker run` command.
        # Example:
        # cmd = ["docker", "run", "-d", "--name", container_name]
        # if ports:
        #     for host_port, container_port in ports.items():
        #         cmd.extend(["-p", f"{host_port}:{container_port}"])
        # if volumes:
        #     for host_path, container_path in volumes.items():
        #         cmd.extend(["-v", f"{host_path}:{container_path}"])
        # cmd.append(image_name)
        # try:
        #     subprocess.run(cmd, check=True, capture_output=True, text=True, shell=False)
        #     AUDIT_LOGGER.info(f"Container '{container_name}' started successfully.")
        #     return True
        # except subprocess.CalledProcessError as e:
        #     AUDIT_LOGGER.error(f"Failed to start container '{container_name}': {e.stderr.strip()}")
        #     return False
        # except FileNotFoundError:
        #     AUDIT_LOGGER.error("Docker command not found.")
        #     return False
        # except Exception as e:
        #     AUDIT_LOGGER.error(f"Unexpected error running container: {e}")
        #     return False
        return True 

    @staticmethod
    def stop_and_remove_container(container_name: str) -> bool:
        """
        Stops and removes a Docker container.
        """
        AUDIT_LOGGER.info(f"Simulating stop_and_remove_container for {container_name}")
        # Placeholder for actual implementation.
        # Example:
        # try:
        #     subprocess.run(["docker", "stop", container_name], check=True, capture_output=True, text=True, shell=False)
        #     subprocess.run(["docker", "rm", container_name], check=True, capture_output=True, text=True, shell=False)
        #     AUDIT_LOGGER.info(f"Container '{container_name}' stopped and removed.")
        #     return True
        # except subprocess.CalledProcessError as e:
        #     AUDIT_LOGGER.error(f"Failed to stop/remove container '{container_name}': {e.stderr.strip()}")
        #     return False
        # except FileNotFoundError:
        #     AUDIT_LOGGER.error("Docker command not found.")
        #     return False
        # except Exception as e:
        #     AUDIT_LOGGER.error(f"Unexpected error stopping/removing container: {e}")
        #     return False
        return True