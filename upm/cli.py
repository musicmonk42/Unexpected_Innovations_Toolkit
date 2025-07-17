# upm/cli.py

import os
import asyncio
import typer
import traceback
import secrets
import re
import sys
import yaml
from typing import Optional, List, Any

# --- Version ---
__version__ = "0.1.0"

# --- UPM Core Imports ---
from upm.core import UniversalPackageManager
from upm.logging_utils import AUDIT_LOGGER, redact_secrets

# --- Main Typer App Definition ---
app_cli = typer.Typer(
    name="upm",
    help="A Universal Package Manager for secure, cross-ecosystem dependency management.",
    no_args_is_help=True
)

state = {"verbose": False}

def version_callback(value: bool):
    if value:
        print(f"UPM Version: {__version__}")
        raise typer.Exit()

@app_cli.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output for debugging."),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, is_eager=True),
):
    """UPM: The Universal Package Manager."""
    state["verbose"] = verbose

def handle_error(operation: str, error: Exception):
    """Provides user-friendly error messages and suggestions."""
    error_msg = str(error)
    fix_suggestions = {
        "Policy blocked": "Check your '.unipkgpolicy.yaml' for 'blocked_packages' or 'allowed_packages' rules.",
        "No plugin found": "Ensure the plugin for this ecosystem is installed. Run 'upm doctor'.",
        "tampered with": "The manifest's integrity check failed. If intentional, run 'upm lock'.",
        "API key is required": "Set the UPM_API_KEY environment variable or use 'upm setup' to configure it.",
        "Permission denied": "Check file/folder permissions or run with appropriate privileges."
    }
    suggestion = "Review the error message, run 'upm doctor', or use --verbose for a detailed traceback."
    for pattern, hint in fix_suggestions.items():
        if re.search(pattern, error_msg, re.IGNORECASE):
            suggestion = hint
            break

    typer.secho(f"🚫 Error during {operation}: {error_msg}", fg=typer.colors.RED, err=True)
    typer.secho(f"💡 Suggestion: {suggestion}", fg=typer.colors.YELLOW, err=True)
    if state["verbose"]:
        typer.secho("\n📋 Detailed Traceback:", fg=typer.colors.BRIGHT_BLACK, err=True)
        typer.secho(redact_secrets(traceback.format_exc()), fg=typer.colors.BRIGHT_BLACK, err=True)
    
    raise typer.Exit(code=1)

# --- CLI Commands ---

@app_cli.command("install")
def install_cmd(
    ecosystem: str = typer.Argument(..., help="The package ecosystem (e.g., pip, npm)."),
    name: str = typer.Argument(..., help="The name of the package."),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="The version constraint."),
):
    """Install a package and add it to the manifest."""
    try:
        upm = UniversalPackageManager(**state)
        result = asyncio.run(upm.install(ecosystem, name, version))
        # FIX: Use attribute access (.success) for Pydantic models
        if result.success:
            typer.secho(f"✅ Successfully installed {name} in {ecosystem}.", fg=typer.colors.GREEN)
        else:
            # FIX: Use attribute access (.errors) for Pydantic models
            raise Exception(result.errors[0] if result.errors else "Unknown installation error.")
    except Exception as e:
        handle_error(f"install of {name}", e)

@app_cli.command("setup")
def setup_wizard():
    """Run an interactive wizard to create a .unipkgrc configuration file."""
    typer.secho("🚀 Welcome to the UPM Configuration Wizard!", fg=typer.colors.CYAN)
    if os.path.exists(".unipkgrc"):
        if not typer.confirm("A .unipkgrc file already exists. Do you want to overwrite it?"):
            raise typer.Abort()

    config = {"security": {}, "notifications": {"email": {"enabled": False}, "slack": {"enabled": False}}}

    if typer.confirm("Enable manifest and log encryption? (Recommended)"):
        config["security"]["encrypt_data"] = True
    if typer.confirm("Enable manifest and lockfile signing for integrity checks?"):
        config["security"]["require_signatures"] = True

    if typer.confirm("Enable email notifications for errors?"):
        config["notifications"]["email"]["enabled"] = True
        config["notifications"]["email"]["recipient"] = typer.prompt("Recipient email address")
        config["notifications"]["email"]["sender"] = typer.prompt("Sender email address")
        config["notifications"]["email"]["smtp_server"] = typer.prompt("SMTP server hostname")
        typer.secho("Note: Set the SMTP password via the UPM_EMAIL_PASSWORD environment variable.", fg=typer.colors.YELLOW)

    if typer.confirm("Enable Slack notifications for errors?"):
        config["notifications"]["slack"]["enabled"] = True
        config["notifications"]["slack"]["channel"] = typer.prompt("Slack channel (e.g., #alerts)")
        typer.secho("Note: Set the Slack token or webhook URL via the UPM_SLACK_TOKEN or config file, respectively.", fg=typer.colors.YELLOW)

    try:
        with open(".unipkgrc", "w") as f:
            yaml.dump(config, f, indent=2, sort_keys=False)
        typer.secho("\n✅ Successfully created .unipkgrc configuration file.", fg=typer.colors.GREEN)
    except Exception as e:
        handle_error("config file creation", e)

@app_cli.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", help="The host to bind the API server to."),
    port: int = typer.Option(8000, help="The port for the API server."),
    allow_insecure: bool = typer.Option(False, help="DANGER: Allow the API to run without an API key."),
):
    """Launches the UPM FastAPI server with secure-by-default key handling."""
    try:
        upm = UniversalPackageManager(**state)
        api_key = os.environ.get("UPM_API_KEY") or upm.config.get("security", {}).get("api_key")

        if not api_key and not allow_insecure:
            raise ValueError("API key is required to start the server. Configure it in .unipkgrc, set UPM_API_KEY, or use --allow-insecure for development.")
        
        if not api_key and allow_insecure:
            typer.secho("⚠️ Security Warning: Starting API server in insecure mode without authentication!", fg=typer.colors.YELLOW, err=True)
            AUDIT_LOGGER.critical("API server started in insecure mode without an API key.")
        
        typer.secho(f"🚀 Starting API server on http://{host}:{port}", fg=typer.colors.GREEN)
        typer.secho("Use Ctrl+C to shut down.", fg=typer.colors.CYAN)
        
        typer.echo("(Placeholder: In a real application, the FastAPI/uvicorn server would run here.)")
        
    except Exception as e:
        handle_error("API server", e)

def main():
    app_cli()

if __name__ == "__main__":
    main()