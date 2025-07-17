# DOCKER.md

## Running UPM Plugin Entrypoint Securely in Docker

This project is designed to be executed within a locked-down Docker container for maximum isolation and auditability.  
**We strongly recommend using Docker (or equivalent container runtime) for all plugin execution in production.**

---

## Quick Start: One-Off Plugin Call

Assuming you have your plugin files and `entrypoint.py` in the `upm/` directory, and your config as `upm_config.json`:

```bash
docker run --rm \
    --name upm-plugin-$(uuidgen | cut -c1-8) \
    --user 65534:65534 \
    --read-only \
    --network=none \
    -v "$PWD/upm:/app:ro" \
    -w /app \
    -e UPM_CONFIG_PATH=/app/upm_config.json \
    python:3.11-alpine \
    python entrypoint.py PipPlugin install '{"args":["requests"],"kwargs":{}}'
Explanation of the main flags:

--rm – Remove the container after completion (no traces left).

--user 65534:65534 – Run as nobody:nogroup for least privilege.

--read-only – Prevent the container from writing to the mounted filesystem.

--network=none – Disable all outbound/inbound networking.

-v ...:/app:ro – Mount your plugin/code/config directory read-only.

-w /app – Set the working directory for execution.

-e UPM_CONFIG_PATH=... – Point to your config file inside the container.

python:3.11-alpine – Minimal, secure Python base image.

Tip: Add -v $PWD/logs:/app/logs if you want to persist logs outside the container.

Recommended Dockerfile (Advanced Usage)
If you want to build your own minimal image:

dockerfile
Copy
Edit
FROM python:3.11-alpine

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

USER 65534:65534
ENTRYPOINT ["python", "entrypoint.py"]
Build: docker build -t upm-secure .

Run:

bash
Copy
Edit
docker run --rm --read-only --network=none -v "$PWD:/app:ro" upm-secure PipPlugin install '{"args":["requests"],"kwargs":{}}'
Security Practices
Run with --read-only and as a non-root user.

Disable the network unless your plugin absolutely requires it (and then tightly control egress).

Never mount sensitive host directories. Only mount what is needed (plugins, config, output dir).

Use a unique container per plugin call. This prevents persistence or cross-plugin attacks.

Rotate/monitor logs by mounting a host directory or using Docker logging drivers.

Volume Management
If your plugins write output or logs, mount a host volume:

bash
Copy
Edit
docker run ... -v "$PWD/logs:/app/logs"
Update your config or environment so plugins write to /app/logs only.

Troubleshooting
Permission errors:
Make sure the files in the mounted directory are readable by UID/GID 65534.

Missing dependencies:
Add them to your Dockerfile or use a custom image with all required packages.

Plugin not found:
Check your config and that the plugin Python files are present in /app inside the container.

Further Hardening
Use AppArmor/SELinux profiles for even tighter host policy (see SECURITY.md).

Consider using gVisor or similar sandboxes for further process isolation.

For high assurance, sign and verify plugin files.

Resources
Docker Security Best Practices

Official Python Docker Images

JSON Schema

Docker isolation is the recommended way to safely execute any plugin code. If you have questions or want to suggest improvements, open an issue or PR.