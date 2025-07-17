# tests/test_docker.py
import pytest
import os
import json
import logging
import subprocess
import shutil
from unittest.mock import patch, MagicMock

# Import the DockerBuilder
from upm.docker import DockerBuilder
from upm.logging_utils import AUDIT_LOGGER

# --- Fixtures ---

@pytest.fixture
def temp_project_root(tmp_path):
    """Provides a temporary directory for Dockerfile and build logs."""
    return tmp_path

@pytest.fixture(autouse=True)
def caplog_audit(caplog):
    """Fixture to capture audit logs specifically."""
    logger = logging.getLogger("unipkg_audit")
    caplog.clear()
    handler = caplog.handler
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield caplog
    logger.removeHandler(handler)
    caplog.clear()


# --- Standard Functional Tests (Using Mocks) ---

class TestDockerBuilderFunctionality:
    def test_build_docker_image_no_dockerfile(self, tmp_path):
        """Test behavior when Dockerfile is not found."""
        with patch('subprocess.run') as mock_run:
            result = DockerBuilder.build_docker_image(str(tmp_path), "test-image")
            assert result is False
            mock_run.assert_not_called()

    def test_build_docker_image_docker_daemon_down(self, temp_project_root, caplog_audit):
        """Test behavior when Docker daemon is not running."""
        (temp_project_root / "Dockerfile").touch()
        with patch('subprocess.run', side_effect=subprocess.CalledProcessError(1, "docker build", stderr="Cannot connect to the Docker daemon")) as mock_run:
            result = DockerBuilder.build_docker_image(str(temp_project_root), "test-image")
            assert result is False
            assert "Docker daemon is not running or accessible" in caplog_audit.text

    def test_build_docker_image_build_failure(self, temp_project_root, caplog_audit):
        """Test behavior when the 'docker build' command fails."""
        (temp_project_root / "Dockerfile").touch()
        with patch('subprocess.run', side_effect=subprocess.CalledProcessError(1, "docker build", stderr="Build error")) as mock_run:
            result = DockerBuilder.build_docker_image(str(temp_project_root), "fail-image")
            assert result is False
            assert "Docker build failed for image 'fail-image'" in caplog_audit.text

    def test_build_success_with_clean_trivy_scan(self, temp_project_root, caplog_audit):
        """Test successful build and a clean Trivy scan using mocks."""
        (temp_project_root / "Dockerfile").touch()
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0), # build
                MagicMock(returncode=0, stdout=json.dumps({"Results": []})) # trivy
            ]
            result = DockerBuilder.build_docker_image(str(temp_project_root), "safe-image")
            assert result is True
            assert "passed vulnerability scan" in caplog_audit.text
            assert mock_run.call_count == 2

# --- NEW: Integration Tests (Requires Docker and Trivy to be installed) ---

@pytest.mark.skipif(not (shutil.which("docker") and shutil.which("trivy")), reason="Docker and Trivy CLIs are required for integration tests")
class TestDockerBuilderIntegration:
    
    def cleanup_docker_image(self, image_tag: str):
        """Helper to remove a docker image after a test."""
        try:
            subprocess.run(["docker", "rmi", "-f", image_tag], check=True, capture_output=True)
            print(f"Cleaned up Docker image: {image_tag}")
        except subprocess.CalledProcessError as e:
            # It's okay if the image wasn't there to be removed
            print(f"Could not remove docker image {image_tag}: {e.stderr.decode()}")

    def test_real_build_with_minimal_dockerfile(self, temp_project_root, caplog_audit):
        """
        HIGH PRIORITY: Tests a real Docker build of a minimal Dockerfile and
        asserts that the image is created.
        """
        image_tag = "upm-test-suite/real-build:latest"
        dockerfile_content = 'FROM alpine:3.19\nRUN echo "hello world"'
        (temp_project_root / "Dockerfile").write_text(dockerfile_content)
        
        try:
            # This test runs a real build but skips the Trivy scan
            result = DockerBuilder.build_docker_image(str(temp_project_root), image_tag, skip_trivy=True)
            assert result is True
            assert f"Successfully built Docker image: {image_tag}" in caplog_audit.text
            
            # Verify the image exists locally
            res = subprocess.run(["docker", "images", "-q", image_tag], check=True, capture_output=True, text=True)
            assert res.stdout.strip() != ""

        finally:
            # Ensure the created image is removed after the test
            self.cleanup_docker_image(image_tag)

    def test_build_fails_on_vulnerable_image_scan(self, temp_project_root, caplog_audit):
        """
        MEDIUM PRIORITY: Tests that the build process fails if Trivy finds
        vulnerabilities in a known-vulnerable base image.
        """
        image_tag = "upm-test-suite/vuln-positive:latest"
        # Use an old, known-vulnerable base image
        dockerfile_content = 'FROM python:3.8-slim-buster'
        (temp_project_root / "Dockerfile").write_text(dockerfile_content)

        try:
            # Build and scan; this should fail because Trivy will find issues
            result = DockerBuilder.build_docker_image(str(temp_project_root), image_tag)
            
            assert result is False
            assert "failed vulnerability scan with" in caplog_audit.text
            assert "CRITICAL" in caplog_audit.text or "HIGH" in caplog_audit.text
        
        finally:
            # Cleanup the image which may or may not have been created
            self.cleanup_docker_image(image_tag)