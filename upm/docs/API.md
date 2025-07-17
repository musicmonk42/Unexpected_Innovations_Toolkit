UPM Web API – Programmatic Control
The UPM Web API allows programmatic, authenticated, and automated access to Universal Package Manager features.

It is built with FastAPI (async, high-performance) and designed for CI/CD, platform automation, and internal developer tooling.

🚀 Starting the API Server
Start the API with:

```sh
unipkg serve_api [--host <host>] [--port <port>] [--api-key <key>] [--allow-insecure-host]
--host <host>: IP/interface to bind (default: 127.0.0.1)

--port <port>: Port to bind (default: 8000)

--api-key <key>: API key for authentication; overrides .unipkgrc and UPM_API_KEY env var.

--allow-insecure-host: DANGER – allows binding to 0.0.0.0 without API key; for isolated dev/test only.

Security Warnings
Never bind to 0.0.0.0 in production unless you fully understand the risk and have strong auth configured.
If no API key is configured, the API runs in open-access mode (with a console warning).
Never run open-access outside isolated/dev environments.

OAuth 2.0 support: Configure via .unipkgrc (see below).

🔑 Authentication
Two supported methods: API Key and OAuth 2.0.

API Key Authentication
Add your API key via the X-API-Key HTTP header.

API key is sourced from:

--api-key CLI argument

UPM_API_KEY environment variable

api_key field in .unipkgrc

Behavior:

If an API key is set, all endpoints require a matching X-API-Key header.

No API key = open-access, with a warning.

Invalid keys get a 401 with an X-API-Key challenge.

OAuth 2.0 Authentication
Token endpoint: POST /token (password grant)

Configure client_id and client_secret in .unipkgrc under security.oauth.

Use Authorization: Bearer <token> for all other endpoints.

Token request example:

sh
Copy
Edit
curl -X POST "http://127.0.0.1:8000/token" \
  -d "grant_type=password&username=user&password=pass&client_id=your_client_id&client_secret=your_client_secret"
🌐 API Endpoints
All endpoints use Content-Type: application/json for requests/responses.

GET /
Health check/welcome. No authentication required.

Response:

json
Copy
Edit
{
  "message": "Welcome to unipkg API!",
  "version": "1.1.0"
}
POST /install
Install a package in a given ecosystem.

Authentication: Required (API key or OAuth token).

Request Body:

json
Copy
Edit
{
  "eco": "pip",  // Ecosystem: pip, npm, cargo, etc.
  "name": "requests",
  "version_constraint": "==2.28.1",
  "dry_run": false
}
Success (200):

json
Copy
Edit
{
  "status": "success",
  "message": "Successfully installed requests from pip",
  "ecosystem": "pip",
  "package": "requests",
  "version": "2.28.1"
}
Error (400):

json
Copy
Edit
{
  "detail": "Failed to install requests from pip: Package blocked by policy",
  "error_code": "POLICY_VIOLATION"
}
GET /list
List all installed packages (optionally per-ecosystem).

Authentication: Required.

Query parameter: eco (optional)

Success (200):

json
Copy
Edit
[
  {"ecosystem": "pip", "name": "requests", "version": "2.28.1"},
  {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}
]
Error (400):

json
Copy
Edit
{
  "detail": "Invalid ecosystem: unknown_eco",
  "error_code": "INVALID_ECOSYSTEM"
}
GET /doctor
Run a full health check for all or a specified ecosystem.

Authentication: Required.

Query parameter: eco (optional)

Success (200):

json
Copy
Edit
{
  "status": "success",
  "checks": [
    "Checking system environment... ✅",
    "pip in PATH (Found at /usr/bin/pip (pip 23.0.1)) ✅",
    "Required Python modules: tqdm ✅",
    "System check complete."
  ]
}
Error (500):

json
Copy
Edit
{
  "detail": "Doctor check failed: Missing binary npm",
  "error_code": "DOCTOR_CHECK_FAILED"
}
POST /token
Obtain an OAuth 2.0 access token (password flow).

Authentication: None (used for login).

Request Body:

json
Copy
Edit
{
  "grant_type": "password",
  "username": "string",
  "password": "string",
  "client_id": "string",
  "client_secret": "string"
}
Success (200):

json
Copy
Edit
{
  "access_token": "your_access_token",
  "token_type": "bearer"
}
Error (401):

json
Copy
Edit
{
  "detail": "Invalid credentials",
  "error_code": "INVALID_CREDENTIALS"
}
📚 Example Usage
Start API with API Key
sh
Copy
Edit
unipkg serve_api --host 127.0.0.1 --port 8000 --api-key my_secret_api_key
Authenticated Requests (API Key)
sh
Copy
Edit
# Install a package
curl -X POST "http://127.0.0.1:8000/install" \
     -H "X-API-Key: my_secret_api_key" \
     -H "Content-Type: application/json" \
     -d '{"eco":"pip","name":"fastapi","version_constraint":"^0.116.0"}'

# List installed packages
curl -X GET "http://127.0.0.1:8000/list?eco=pip" \
     -H "X-API-Key: my_secret_api_key"

# Run doctor check
curl -X GET "http://127.0.0.1:8000/doctor" \
     -H "X-API-Key: my_secret_api_key"
OAuth 2.0 Requests
sh
Copy
Edit
# Obtain an access token
curl -X POST "http://127.0.0.1:8000/token" \
     -d "grant_type=password&username=user&password=pass&client_id=your_client_id&client_secret=your_client_secret"

# Use token for package install
curl -X POST "http://127.0.0.1:8000/install" \
     -H "Authorization: Bearer your_access_token" \
     -H "Content-Type: application/json" \
     -d '{"eco":"pip","name":"fastapi","version_constraint":"^0.116.0"}'
🛠️ API Configuration
Configure credentials in .unipkgrc (never store secrets in plain text in VCS):

yaml
Copy
Edit
security:
  api_key: my_secret_api_key      # Or use UPM_API_KEY env var
  oauth:
    client_id: your_client_id
    client_secret: your_client_secret   # Use UPM_OAUTH_SECRET env var for production!
📖 Interactive API Docs
When running, access the interactive OpenAPI (Swagger) UI at:

arduino
Copy
Edit
http://127.0.0.1:8000/docs
You can test endpoints, see schemas, and experiment securely.

🔒 Security & Compliance Reminders
Never expose this API on an open network without authentication.

Always use strong, unique API keys/secrets (rotate regularly).

Log and monitor all API usage for suspicious activity.

Run the API in a dedicated, isolated environment when possible.

Review audit logs and SBOMs regularly to ensure supply-chain integrity.

For more, see: USAGE.md, SECURITY.md, and docs/CONFIGURATION.md

🛡️ Sandboxing and Plugin Execution Security
Plugin Sandboxing:
Any API call that triggers plugin actions (e.g. install, list, doctor) executes those plugins in a fully isolated subprocess for security.
This process isolation ensures that plugins cannot directly access or crash the main UPM API server process.

On Linux: Subprocesses provide strong isolation. For maximum security, run the API in a Docker container or VM if you use community or untrusted plugins.

On Windows/macOS: Subprocess isolation is enforced, but is not a full OS sandbox.

All Plugins: Must conform to the UPM sandbox entrypoint pattern (see PLUGINS.md and SECURITY.md).

Caveats:

Subprocess isolation is NOT the same as a true OS or container sandbox.

Malicious or misbehaving plugins cannot crash your server, but may still try to consume system resources.

Audit logs will record all plugin execution, failures, or timeouts.

References:
See SECURITY.md, PLUGINS.md, LOGGING.md.

End of API.md