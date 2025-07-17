# upm/logging_utils.py

import logging
import os
import sys
import stat
import platform
import json
import time
import re
import queue
import threading
from typing import Any, Dict, Optional, List
from enum import Enum
from logging.handlers import QueueHandler, RotatingFileHandler
import getpass
import shutil
import asyncio
import gzip

# --- Conditional Imports ---
try:
    from cryptography.fernet import Fernet, InvalidToken
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    Fernet, InvalidToken = None, type('InvalidToken', (Exception,), {})
    _CRYPTOGRAPHY_AVAILABLE = False

# Conditional import for ConcurrentRotatingFileHandler on Windows
_CONCURRENT_LOG_HANDLER_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import concurrent_log_handler
        from concurrent_log_handler import ConcurrentRotatingFileHandler
        _CONCURRENT_LOG_HANDLER_AVAILABLE = True
    except ImportError:
        pass

try:
    import win32security
    import ntsecuritycon as con
    _WIN32_SECURITY_AVAILABLE = True
except ImportError:
    _WIN32_SECURITY_AVAILABLE = False

# === Asynchronous Logging Infrastructure ===
_log_queue: queue.Queue = queue.Queue(maxsize=10000)
_log_listener_thread: Optional[threading.Thread] = None
_remote_upload_config_global: Optional[Dict[str, Any]] = None
_log_file_path_global: Optional[str] = None

class DroppingQueueHandler(QueueHandler):
    """A custom QueueHandler that drops the oldest log record when the queue is full."""
    def enqueue(self, record: logging.LogRecord):
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            try:
                self.queue.get_nowait()  # Drop oldest
                self.queue.put_nowait(record)  # Try again
            except queue.Empty:
                pass

def _log_listener_worker(handlers: list):
    """Worker that pulls logs from the queue and dispatches to handlers."""
    while True:
        try:
            record = _log_queue.get()
            if record is None:  # Sentinel to exit
                for handler in handlers:
                    handler.flush()
                    handler.close()
                _log_queue.task_done()
                break
            for handler in handlers:
                if record.levelno >= handler.level:
                    handler.emit(record)
        except Exception:
            import traceback
            traceback.print_exc(file=sys.stderr)
        finally:
            if 'record' in locals() and record is not None:
                _log_queue.task_done()

# === User Identification & Redaction ===
def get_current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"

def redact_secrets(msg: str) -> str:
    if not isinstance(msg, str):
        msg = str(msg)
    keywords = ('api_key', 'apikey', 'key', 'token', 'password', 'secret', 'auth', 'bearer', 'credential', 'pass', 'access_token', 'refresh_token', 'client_secret', 'private_key', 'aws_access_key_id', 'aws_secret_access_key')
    patterns = [
        (re.compile(r'(["\']?(?:' + '|'.join(keywords) + r')["\']?\s*[:=]\s*["\']?)([^,\s"\']+)'), r'\1[REDACTED]'),
        (re.compile(r'(Authorization:\s*Bearer\s+)[a-zA-Z0-9\-_.~+/]+=*'), r'\1[REDACTED]'),
        (re.compile(r'AKIA[0-9A-Z]{16}'), 'AKIA[REDACTED]'),
        (re.compile(r'ey[J][A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'), '[REDACTED_JWT]')
    ]
    for pattern, replacement in patterns:
        msg = pattern.sub(replacement, msg)
    return msg

# === Audit Log Enum ===
class AuditOperation(Enum):
    INSTALL = "install"
    UNINSTALL = "uninstall"
    UPGRADE = "upgrade"
    LIST = "list"
    OUTDATED = "outdated"
    DOCTOR = "doctor"
    SUGGEST = "suggest"
    AUTO_FIX = "auto_fix"
    LOCK = "lock"
    PROJECT_INIT = "init_project"
    POLICY_CHECK = "policy_check"
    SECURITY_EVENT = "security_event"
    CLI_INVOKE = "cli_invoke"
    NOTIFICATION = "notification"
    UNKNOWN = "unknown"

# === Secure Log File Handler ===
class SecureRotatingFileHandler(RotatingFileHandler):
    """A rotating file handler that ensures secure file permissions on both POSIX and Windows."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ensure_secure_permissions()

    def doRollover(self):
        super().doRollover()
        self._ensure_secure_permissions()

    def _ensure_secure_permissions(self):
        if platform.system() == "Windows":
            self._ensure_secure_permissions_windows()
        else:
            self._ensure_secure_permissions_posix()

    def _ensure_secure_permissions_posix(self):
        try:
            os.chmod(self.baseFilename, stat.S_IRUSR | stat.S_IWUSR)
        except (OSError, Exception) as e:
            logging.warning(f"Could not set secure POSIX permissions on log file {self.baseFilename}: {e}")

    def _ensure_secure_permissions_windows(self):
        if not _WIN32_SECURITY_AVAILABLE:
            logging.warning("win32security not available. Cannot set secure ACLs on Windows log files.")
            return
        try:
            user, _, _ = win32security.LookupAccountName("", get_current_user())
            system, _, _ = win32security.LookupAccountName("", "SYSTEM")
            sd = win32security.GetFileSecurity(self.baseFilename, win32security.DACL_SECURITY_INFORMATION)
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE, user)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, system)
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(self.baseFilename, win32security.DACL_SECURITY_INFORMATION, sd)
        except Exception as e:
            logging.warning(f"Could not set secure Windows ACLs on log file {self.baseFilename}: {e}")

# === Log Formatters ===
class JSONFormatter(logging.Formatter):
    """Formatter that outputs log records as a structured JSON string."""
    def format(self, record: logging.LogRecord) -> str:
        standard_attrs = {'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename', 'funcName', 'levelname', 'levelno', 'lineno', 'module', 'msecs', 'message', 'msg', 'name', 'pathname', 'process', 'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName', 'taskName'}
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "user": get_current_user(),
            "operation": getattr(record, "operation", AuditOperation.UNKNOWN.name),
            "message": redact_secrets(record.getMessage()),
            "logger": record.name
        }
        if hasattr(record, "context"):
            log_entry["context"] = json.loads(json.dumps(record.context, default=lambda o: f"<unserializable: {type(o).__name__}>"))
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        extra_fields = {k: v for k, v in record.__dict__.items() if k not in standard_attrs and k not in log_entry}
        if extra_fields:
            log_entry.update(extra_fields)
        try:
            return json.dumps(log_entry)
        except (TypeError, ValueError) as e:
            logging.error(f"Failed to serialize log entry to JSON: {e}")
            return json.dumps({"error": f"JSON serialization failed: {e}", "original_message": record.getMessage()})

class HumanReadableFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"{time.strftime('%H:%M:%S')} - {record.levelname:<8} - {record.threadName:<10} - {redact_secrets(record.getMessage())}"

class EncryptedFormatter(logging.Formatter):
    def __init__(self, fernet_instance: "Fernet"):
        super().__init__()
        if not _CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography is required for EncryptedFormatter.")
        self.fernet = fernet_instance
        self.json_formatter = JSONFormatter()

    def format(self, record: logging.LogRecord) -> str:
        return self.fernet.encrypt(self.json_formatter.format(record).encode('utf-8')).decode('utf-8')

# === Logger Initialization & Management ===
AUDIT_LOGGER = logging.getLogger("unipkg_audit")
AUDIT_LOGGER.propagate = False
APP_LOGGER = AUDIT_LOGGER

def sign_log_file_for_upload(file_path: str) -> str:
    signed_file_path = f"{file_path}.signed"
    try:
        shutil.copy2(file_path, signed_file_path)
        with open(signed_file_path, 'a') as f:
            f.write("\n---DUMMY SIGNATURE BLOCK---")
    except Exception as e:
        AUDIT_LOGGER.error(f"Failed to create signed log file: {e}")
        return file_path
    return signed_file_path

async def _upload_logs_on_shutdown(remote_upload_config: dict, log_file_path: str):
    if not remote_upload_config.get("enabled"):
        return
    if not (s3_bucket := remote_upload_config.get("s3_bucket")):
        return
    try:
        import boto3
        if not os.path.exists(log_file_path):
            return
        compressed_log_path = f"{log_file_path}.gz"
        with open(log_file_path, 'rb') as f_in:
            with gzip.open(compressed_log_path, 'wb') as f_out:
                f_out.writelines(f_in)
        signed_log_path = sign_log_file_for_upload(compressed_log_path)
        s3_key = f"{remote_upload_config.get('s3_prefix', 'logs/')}{os.path.basename(signed_log_path)}_{int(time.time())}.log.gz"
        await asyncio.to_thread(boto3.client('s3').upload_file, signed_log_path, s3_bucket, s3_key)
        os.remove(signed_log_path)
        os.remove(compressed_log_path)
        log_audit(logging.INFO, f"Successfully uploaded log file {os.path.basename(log_file_path)} to S3 bucket {s3_bucket}", AuditOperation.NOTIFICATION)
    except Exception as e:
        sys.stderr.write(f"ERROR: Failed to upload audit log to S3: {e}\n")
        log_audit(logging.ERROR, f"Failed to upload audit log to S3: {e}", AuditOperation.UNKNOWN)

# Global state for handler management
_global_log_handlers: List[logging.Handler] = []
_has_configured_once = False

def configure_logging(**kwargs: Any):
    global _log_listener_thread, _remote_upload_config_global, _log_file_path_global, _global_log_handlers, _has_configured_once

    # Always clear existing handlers to ensure a clean slate for configuration
    for handler in list(AUDIT_LOGGER.handlers):
        try:
            handler.close()
        except Exception:
            pass
        AUDIT_LOGGER.removeHandler(handler)
    
    _global_log_handlers.clear()

    # Initialize global settings
    _log_file_path_global = kwargs.get("log_file_path", "unipkg_audit.log")
    _remote_upload_config_global = kwargs.get("remote_upload_config")

    # Create directory for log file
    log_dir = os.path.dirname(_log_file_path_global) or '.'
    os.makedirs(log_dir, exist_ok=True)

    # Use direct FileHandler for tests to avoid queue issues
    if kwargs.get("disable_concurrent_log_handler", False):
        file_handler = logging.FileHandler(_log_file_path_global, mode="a")
    else:
        file_handler_class = ConcurrentRotatingFileHandler if platform.system() == "Windows" and _CONCURRENT_LOG_HANDLER_AVAILABLE else RotatingFileHandler
        file_handler = file_handler_class(
            _log_file_path_global,
            maxBytes=kwargs.get("log_max_bytes", 10 * 1024 * 1024),
            backupCount=kwargs.get("log_backup_count", 5)
        )

    # Setup Formatter
    formatter: logging.Formatter
    if kwargs.get("log_format", "text").lower() == "json":
        formatter = JSONFormatter()
    else:
        formatter = HumanReadableFormatter()

    if kwargs.get("encrypt_logs"):
        if not (key_path := kwargs.get("encryption_key_path")):
            raise ValueError("encryption_key_path is required for encrypted logs.")
        try:
            from cryptography.fernet import Fernet
            with open(key_path, 'rb') as f:
                fernet_instance = Fernet(f.read())
            formatter = EncryptedFormatter(fernet_instance)
        except ImportError:
            sys.stderr.write("ERROR: Cryptography library not found. Encrypted logging disabled.\n")
            formatter = HumanReadableFormatter()
        except Exception as e:
            sys.stderr.write(f"ERROR: Failed to load encryption key for logging: {e}. Encrypted logging disabled.\n")
            formatter = HumanReadableFormatter()

    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)  # Set to DEBUG to capture all logs
    _global_log_handlers.append(file_handler)

    # Setup Console Handler (if verbose)
    if kwargs.get("verbose"):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(HumanReadableFormatter())
        console_handler.setLevel(logging.DEBUG)
        _global_log_handlers.append(console_handler)

    # Use direct FileHandler for tests, otherwise use QueueHandler
    if kwargs.get("disable_concurrent_log_handler", False):
        AUDIT_LOGGER.addHandler(file_handler)
        if kwargs.get("verbose"):
            AUDIT_LOGGER.addHandler(console_handler)
    else:
        AUDIT_LOGGER.addHandler(DroppingQueueHandler(_log_queue))
        if _log_listener_thread is None or not _log_listener_thread.is_alive():
            _log_listener_thread = threading.Thread(target=_log_listener_worker, args=(_global_log_handlers,), daemon=True)
            _log_listener_thread.start()

    AUDIT_LOGGER.setLevel(logging.DEBUG if kwargs.get("verbose") else logging.INFO)
    _has_configured_once = True

def decrypt_audit_log_file(log_file_path: str, key_path: str) -> str:
    if not _CRYPTOGRAPHY_AVAILABLE:
        return "Error: Cryptography library is required."
    try:
        with open(key_path, 'rb') as f:
            fernet = Fernet(f.read())
        decrypted_lines = []
        open_func = gzip.open if log_file_path.endswith('.gz') else open
        with open_func(log_file_path, 'rt', encoding='utf-8') as f:
            for i, line in enumerate(f):
                stripped = line.strip()
                if stripped:
                    try:
                        decrypted_lines.append(fernet.decrypt(stripped.encode('utf-8')).decode('utf-8'))
                    except InvalidToken:
                        decrypted_lines.append(f'{{"error": "Failed to decrypt log entry #{i+1}"}}')
        return "\n".join(decrypted_lines)
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def flush_logs():
    _log_queue.join()
    for handler in _global_log_handlers:
        handler.flush()

def log_audit(level: int, message: str, operation: AuditOperation, context: Optional[Dict[str, Any]] = None):
    AUDIT_LOGGER.log(level, message, extra={"operation": operation.name, "context": context or {}})

def shutdown_logging():
    global _log_listener_thread, _global_log_handlers, _has_configured_once

    if not _has_configured_once and not _log_listener_thread:
        return

    flush_logs()

    if _remote_upload_config_global and _remote_upload_config_global.get("enabled", False) and _log_file_path_global:
        try:
            asyncio.run(_upload_logs_on_shutdown(_remote_upload_config_global, _log_file_path_global))
        except RuntimeError:
            # This can happen if the event loop is already running, ignore.
            pass
        except Exception as e:
            sys.stderr.write(f"ERROR: Unexpected error during log upload on shutdown: {e}\n")

    if _log_listener_thread and _log_listener_thread.is_alive():
        try:
            _log_queue.put(None)
            _log_listener_thread.join(timeout=5.0)
            if _log_listener_thread.is_alive():
                sys.stderr.write("ERROR: Log listener thread still alive after timeout! Resources might be leaked.\n")
        except Exception as e:
            sys.stderr.write(f"ERROR: Error joining log listener thread: {e}\n")
        finally:
            _log_listener_thread = None

    for handler in AUDIT_LOGGER.handlers[:]:
        AUDIT_LOGGER.removeHandler(handler)
        try:
            handler.close()
        except Exception as e:
            sys.stderr.write(f"ERROR: Failed to close AUDIT_LOGGER handler {handler.__class__.__name__}: {e}\n")

    for handler in _global_log_handlers[:]:
        handler.close()
        _global_log_handlers.remove(handler)

    _has_configured_once = False

# Initial configuration when the module is imported
if not AUDIT_LOGGER.handlers:
    configure_logging(log_file_path="unipkg_initial_startup.log", verbose=False, remote_upload_config={"enabled": False}, disable_concurrent_log_handler=True)