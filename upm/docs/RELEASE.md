# UPM Release Process and Security Measures

**Maintained by:** Unexpected Innovations  

**Release/Disclosure Contact:** [security@unexpectedinnovations.com](mailto:security@unexpectedinnovations.com)  

**Last updated:** 2025-07-16

---

> ⚠️ **SECURITY & TRANSPARENCY WARNING**  
> Every release is signed, auditable, and follows this documented process.  
> All artifacts, SBOMs, and Docker images are cryptographically signed and verifiable via Rekor/Sigstore and GPG.

---

## 📋 Pre-Release Checklist

Complete **ALL** steps before any new release:

| Task                               | Who                  | Tool/Doc Reference              | Status |
|-------------------------------------|----------------------|----------------------------------|--------|
| All tests (unit/integration/sec)    | Developer, Reviewer  | `pytest`, `CONTRIBUTING.md`      |        |
| **Plugin sandbox/process isolation**| Developer, Reviewer  | `PLUGINS.md`, `CONTRIBUTING.md`  |        |
| **All plugins: entrypoint present** | Developer            | `PLUGINS.md`                     |        |
| Code review (security, style)       | Reviewer, Lead       | `SECURITY.md`                    |        |
| Docs updated                        | Developer, Reviewer  | See docs below                   |        |
| Dependency/SBOM audit               | DevOps, Security     | `pip-audit`, `syft`              |        |
| Version bump in manifests           | Developer            | `pyproject.toml`, `CHANGELOG.md` |        |

- **Every plugin MUST be covered by sandbox/process isolation tests.**
- **All plugin files must include the mandatory sandbox entrypoint block.**
- **Release is blocked if any plugin can run unsandboxed or fails isolation tests.**

---

## 🛠️ Build Process

1. **Clean Build Environment**
    ```sh
    rm -rf build/ dist/ .eggs/
    find . -name '__pycache__' -type d -exec rm -r {} +
    find . -name '*.pyc' -delete
    ```

2. **Build Artifacts**
    ```sh
    python -m build
    # Outputs: dist/upm-x.y.z.tar.gz, upm-x.y.z-py3-none-any.whl
    ```

3. **Build Docker Image**
    ```sh
    docker build -t upm:x.y.z .
    ```

---

## 🔒 Security Artifact Generation

### 1. **SBOM (Software Bill of Materials)**
- Generate for both Python and Docker artifacts:
    ```sh
    pip install pip-audit syft
    ./scripts/generate_sbom.sh --python-env .venv --output-dir dist/sbom --format spdx-json
    ./scripts/generate_sbom.sh --docker-image upm:x.y.z --output-dir dist/sbom --format cyclonedx-json
    ```

- **Sign all SBOMs:**
    ```sh
    cd dist/sbom
    gpg --detach-sign --armor upm-x.y.z.spdx.json
    cosign sign --yes upm:x.y.z-sbom
    ```

### 2. **Sign Release Artifacts**
    ```sh
    cd dist
    gpg --detach-sign --armor upm-x.y.z.tar.gz
    gpg --detach-sign --armor upm-x.y.z-py3-none-any.whl
    cosign sign --yes upm:x.y.z
    ```

- **Verify:**  
    - GPG: `gpg --verify ...`
    - Cosign: `cosign verify upm:x.y.z`

---

## 📦 Publishing the Release

1. **PyPI**
    ```sh
    twine upload dist/*
    ```
2. **Docker Hub / Registry**
    ```sh
    docker push upm:x.y.z
    ```
3. **GitHub Release**
    - New tag with version number
    - Attach all signed artifacts, SBOMs, and signatures from `dist/` and `dist/sbom/`
    - Include `CHANGELOG.md` in release notes
4. **Announcements**
    - Website, mailing lists, social media

---

## 🔍 Post-Release Verification

- **Transparency Logs:**  
    - Check Rekor for cosign/Sigstore signatures:
        ```sh
        cosign verify upm:x.y.z
        ```
- **Automated Security Scans:**  
    - Trivy or equivalent:
        ```sh
        trivy image upm:x.y.z
        ```
- **User Feedback:**  
    - Monitor GitHub issues for bug/security reports
    - Encourage users to run `unipkg diagnose`

---

## 🔐 Additional Security Measures

| Measure                  | Enforcement/Location               | Reference               |
|--------------------------|------------------------------------|-------------------------|
| Manifest signing         | All `unipkg.yaml`/`.unipkg.lock`   | `CONFIGURATION.md`      |
| API Security             | OAuth 2.0/API Key for all endpoints| `API.md`, `SECURITY.md` |
| Audit Logs               | S3+KMS upload, encryption          | `LOGGING.md`            |
| **Plugin Verification**  | All plugins checked, signed, **sandboxed** | `PLUGINS.md`      |

---

## ✅ Artifact Trust Policy

| Artifact/Source         | Accepted if Signed | Manual Review       | Blocked by Policy |
|-------------------------|-------------------|---------------------|-------------------|
| Official PyPI/Registry  | Yes               | No                  | No                |
| Official Docker/Hub     | Yes               | No                  | No                |
| 3rd-party unsigned      | No                | N/A                 | Yes               |
| Community (signed)      | Only with manual audit | Yes            | No (if passes)    |

---

## 🏷️ Roles and Responsibilities

- **Release Lead:** Orchestrates release, verifies completion of checklist, final sign-off
- **Developers:** Ensure all code/tests/docs updated, sign artifacts, verify sandboxing
- **Security/DevOps:** Run SBOM, security scans, verify signatures, check transparency logs, **enforce plugin process isolation**
- **Reviewers:** Approve PRs, review CHANGELOG, enforce policies, **verify entrypoint and sandbox tests for plugins**

---

## 🛡️ Disclosure & Remediation

If a vulnerability is discovered, **do not** file a public issue.  
Contact [security@unexpectedinnovations.com](mailto:security@unexpectedinnovations.com) or use a GitHub Security Advisory.  
All critical security issues will be triaged, fixed promptly, and disclosed per [SECURITY.md](SECURITY.md).

---

## 📚 References

| Topic            | Doc/Tool                 |
|------------------|--------------------------|
| Configuration    | [CONFIGURATION.md](CONFIGURATION.md)
| Plugins          | [PLUGINS.md](PLUGINS.md)
| Testing          | [CONTRIBUTING.md](CONTRIBUTING.md)
| Logging          | [LOGGING.md](LOGGING.md)
| API              | [API.md](API.md)
| Security         | [SECURITY.md](SECURITY.md)
| Release/SBOM     | [RELEASE.md](RELEASE.md), [CHANGELOG.md](CHANGELOG.md)
| CI/CD            | `.github/workflows/`, `Dockerfile`
| SBOM/Signing     | `pip-audit`, `syft`, `cosign`, `gpg`, `trivy`

---

**By following this process, all UPM releases are secure, verifiable, transparent, and compliant with the highest supply chain standards.**

---

End of RELEASE.md