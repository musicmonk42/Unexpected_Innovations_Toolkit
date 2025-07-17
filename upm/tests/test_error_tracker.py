# upm/error_tracker.py

import logging
from logging.handlers import RotatingFileHandler
import json
from logging import LogRecord
from typing import Optional, Dict, Any, List
from datetime import datetime
from collections import deque
import os
import stat
import time

if os.name == "nt":
    try:
        from concurrent_log_handler import ConcurrentRotatingFileHandler as RFHandler
    except ImportError:
        logging.warning("concurrent-log-handler not found. Falling back to standard RotatingFileHandler...")
        from logging.handlers import RotatingFileHandler as RFHandler
else:
    from logging.handlers import RotatingFileHandler as RFHandler

class JSONFormatter(logging.Formatter):
    """Formatter for producing logs in line-delimited JSON."""
    def format(self, record: logging.LogRecord) -> str:
        # ... (rest of the class is unchanged) ...
        reserved = {
            'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
            'funcName', 'levelname', 'levelno', 'lineno', 'module',
            'msecs', 'message', 'msg', 'name', 'pathname', 'process',
            'processName', 'relativeCreated', 'stack_info', 'thread',
            'threadName', 'taskName'
        }
        log_data = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat(timespec='milliseconds') + "Z",
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread_id': record.thread,
            'thread_name': record.threadName,
            'process_id': record.process,
            'process_name': record.processName,
        }
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        extras = {k: v for k, v in record.__dict__.items() if k not in reserved}
        log_data.update(extras)
        return json.dumps(log_data, ensure_ascii=False)

class HumanReadableFormatter(logging.Formatter):
    """Formatter that outputs human-readable log messages."""
    def format(self, record: logging.LogRecord) -> str:
        msg = f"{time.strftime('%H:%M:%S')} - {record.levelname:<8} - {record.getMessage()}"
        return msg

class ErrorTracker:
    """
    Advanced ErrorTracker with structured JSON logging, multiple handlers, enhanced exception support,
    and in-memory error tracking for application logic.
    """
    def __init__(self, log_file: str = 'errors.log', level: int = logging.INFO,
                 max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5,
                 console_logging: bool = True, json_format: bool = True):
        # ... (rest of __init__ is unchanged) ...
        self.logger = logging.getLogger('upm.error_tracker')
        self.logger.setLevel(level)
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        text_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d'
        )
        file_formatter = JSONFormatter() if json_format else text_formatter
        console_formatter = text_formatter

        file_handler = RFHandler(log_file, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        if os.name == "posix":
            try:
                os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
            except Exception as e:
                self.logger.warning(f"Could not set secure permissions on log file {log_file}: {e}")

        if console_logging:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        self._errors = deque()
        self.notifier = None
        
    # ... (log_* methods are unchanged) ...
    def log_error(self, msg: str, exc_info: bool = False, extra: Optional[Dict[str, Any]] = None):
        self.logger.error(msg, exc_info=exc_info, extra=extra or {})

    def log_exception(self, msg: str = 'Exception occurred', extra: Optional[Dict[str, Any]] = None):
        self.logger.exception(msg, extra=extra or {})

    def log_info(self, msg: str, extra: Optional[Dict[str, Any]] = None):
        self.logger.info(msg, extra=extra or {})

    def log_warning(self, msg: str, extra: Optional[Dict[str, Any]] = None):
        self.logger.warning(msg, extra=extra or {})

    def log_debug(self, msg: str, extra: Optional[Dict[str, Any]] = None):
        self.logger.debug(msg, extra=extra or {})


    def add_error(self, msg: str, exc_info: bool = False, extra: Optional[Dict[str, Any]] = None):
        """Adds an error to the in-memory deque and also logs it."""
        self._errors.append(msg)
        self.log_error(msg, exc_info=exc_info, extra=extra)

    def get_errors(self) -> List[str]:
        """Returns the list of tracked errors."""
        return list(self._errors)

    def clear_errors(self) -> None:
        """Clears the in-memory list of tracked errors."""
        self._errors.clear()

    def has_errors(self) -> bool:
        """Checks if any errors have been tracked."""
        return len(self._errors) > 0

    def set_notifier(self, notifier: Any) -> None:
        """Sets the notifier instance for sending alerts."""
        self.notifier = notifier
        
    def summarize_and_notify(self, operation: str, verbose: bool = False, severity: str = "ERROR") -> None:
        """Summarizes errors and sends notifications if needed."""
        if self.has_errors():
            summary = f"Operation '{operation}' completed with errors"
            details = "\n- ".join(self._errors)
            full_message = f"{summary}\nDetails:\n- {details}"
            
            self.logger.error(full_message)
            print(f"\n--- 🚫 Operation '{operation}' completed with errors ---")
            for error in self._errors:
                print(f"  - {error}")
            print("--------------------------------------------------")

            if self.notifier:
                # FIX: Wrap notifier calls in try...except to prevent crashes
                try:
                    self.notifier.send_slack(message=full_message, verbose=verbose)
                    if severity.upper() in ["ERROR", "CRITICAL"]:
                        self.notifier.send_email(subject=f"UPM Operation Failed: {operation}", body=full_message, verbose=verbose)
                except Exception as e:
                    self.logger.error(f"Failed to send notification for operation '{operation}'. Error: {e}", exc_info=True)
        else:
            if verbose:
                self.logger.info(f"UPM operation '{operation}' completed successfully.")