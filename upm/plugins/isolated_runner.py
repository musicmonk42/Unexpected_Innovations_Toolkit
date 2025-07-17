# upm/plugins/isolated_runner.py

import sys
import os
import json
import asyncio
import importlib
import hmac
import hashlib
import logging

# --- Platform-Specific Hardening Imports ---
if sys.platform == "linux":
    try:
        import seccomp
        _SECCOMP_AVAILABLE = True
    except ImportError:
        _SECCOMP_AVAILABLE = False
else:
    _SECCOMP_AVAILABLE = False

if os.name == 'posix':
    import resource
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

# --- Isolated Process Logger ---
ISOLATED_LOGGER = logging.getLogger("isolated_runner")
ISOLATED_LOGGER.addHandler(logging.StreamHandler(sys.stderr))
ISOLATED_LOGGER.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - ISOLATED - %(levelname)s - %(message)s')
ISOLATED_LOGGER.handlers[0].setFormatter(formatter)


# === Sandboxing and Hardening Functions ===

def _apply_posix_resource_limits(policy: dict):
    if os.name != 'posix': return
    limits = policy.get("resource_limits", {})
    try:
        if max_cpu := limits.get("max_cpu_seconds"):
            resource.setrlimit(resource.RLIMIT_CPU, (int(max_cpu), int(max_cpu)))
            ISOLATED_LOGGER.info(f"Applied CPU time limit: {max_cpu}s")
        if max_mem_mb := limits.get("max_memory_mb"):
            mem_bytes = int(max_mem_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            ISOLATED_LOGGER.info(f"Applied Memory limit: {max_mem_mb}MB")
    except (ValueError, resource.error) as e:
        ISOLATED_LOGGER.critical(f"CRITICAL: Failed to apply resource limits: {e}. Terminating.", exc_info=True)
        sys.exit(1)

def _apply_windows_job_object_limits(policy: dict):
    if sys.platform != "win32": return
    limits = policy.get("resource_limits", {})
    max_mem_mb = limits.get("max_memory_mb")
    max_cpu_s = limits.get("max_cpu_seconds")
    if not max_mem_mb and not max_cpu_s: return

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [("ReadOperationCount", wintypes.ULARGE_INTEGER), ("WriteOperationCount", wintypes.ULARGE_INTEGER), ("OtherOperationCount", wintypes.ULARGE_INTEGER), ("ReadTransferCount", wintypes.ULARGE_INTEGER), ("WriteTransferCount", wintypes.ULARGE_INTEGER), ("OtherTransferCount", wintypes.ULARGE_INTEGER)]
    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER), ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER), ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.POINTER(wintypes.ULONG)), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        
    kernel32 = ctypes.windll.kernel32
    JobObjectExtendedLimitInformation, JOBOBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_LIMIT_JOB_TIME = 9, 0x00000100, 0x00000004
    job_handle = kernel32.CreateJobObjectW(None, None)
    if not job_handle: return
    process_handle = kernel32.OpenProcess(wintypes.DWORD(0x1010), False, os.getpid())
    if not kernel32.AssignProcessToJobObject(job_handle, process_handle):
        kernel32.CloseHandle(process_handle)
        return
    kernel32.CloseHandle(process_handle)
    limit_info, limit_flags = JOBOBJECT_EXTENDED_LIMIT_INFORMATION(), 0
    if max_mem_mb:
        limit_flags |= JOBOBJECT_LIMIT_PROCESS_MEMORY; limit_info.ProcessMemoryLimit = int(max_mem_mb) * 1024 * 1024
        ISOLATED_LOGGER.info(f"Applying Windows Memory limit via Job Object: {max_mem_mb}MB")
    if max_cpu_s:
        limit_flags |= JOBOBJECT_LIMIT_JOB_TIME; limit_info.BasicLimitInformation.PerJobUserTimeLimit = int(max_cpu_s) * 10_000_000
        ISOLATED_LOGGER.info(f"Applying Windows CPU Time limit via Job Object: {max_cpu_s}s")
    limit_info.BasicLimitInformation.LimitFlags = limit_flags
    if not kernel32.SetInformationJobObject(job_handle, JobObjectExtendedLimitInformation, ctypes.byref(limit_info), ctypes.sizeof(limit_info)):
        ISOLATED_LOGGER.error(f"Failed to set information on Job Object. Error code: {kernel32.GetLastError()}")

def _apply_seccomp_filter(policy: dict):
    if not _SECCOMP_AVAILABLE: return
    permissions, f = policy.get("sandbox_permissions", {}), seccomp.SyscallFilter(defaction=seccomp.KILL)
    essential = ["read", "write", "close", "fstat", "lseek", "mmap", "munmap", "brk", "exit_group", "futex", "getpid", "rt_sigaction", "rt_sigprocmask", "access", "openat", "stat", "lstat"]
    for syscall in essential: f.add_rule(seccomp.ALLOW, syscall)
    if permissions.get("allow_write"): f.add_rules(seccomp.ALLOW, ["rename", "mkdir", "rmdir", "unlink"])
    if permissions.get("allow_network"): f.add_rules(seccomp.ALLOW, ["socket", "connect", "sendto", "recvfrom"])
    if permissions.get("allow_exec"): f.add_rules(seccomp.ALLOW, ["execve", "clone", "fork", "wait4"])
    try:
        f.load()
        ISOLATED_LOGGER.info("Seccomp syscall filter applied.")
    except Exception as e:
        ISOLATED_LOGGER.critical(f"CRITICAL: Failed to apply seccomp filter: {e}. Terminating.", exc_info=True)
        sys.exit(1)


def main():
    try:
        raw_payload = sys.stdin.buffer.read()
        key_hex, signature, json_payload_bytes = raw_payload.split(b'|', 2)
        ipc_key = bytes.fromhex(key_hex.decode())
        expected_signature = hmac.new(ipc_key, json_payload_bytes, hashlib.sha256).hexdigest().encode('utf-8')
        if not hmac.compare_digest(signature, expected_signature):
            raise SecurityException("IPC payload verification failed: Invalid signature.")
        data = json.loads(json_payload_bytes)
        
        # FIX: Correctly unpack kwargs from data
        plugin_module_name, class_name, root, cache, policy, method_name, args, method_kwargs, fernet_lib_key_material = ( # Renamed kwargs to method_kwargs
            data['module'], data['class'], data['root'], data['cache'], data['policy'], data['method'], data['args'], data['kwargs'], data.get('fernet_lib_key_material')
        )
        
        # If encryption is enabled, recreate the Fernet instance
        fernet_instance = None
        if fernet_lib_key_material:
            try:
                from cryptography.fernet import Fernet
                fernet_instance = Fernet(fernet_lib_key_material.encode('utf-8'))
            except ImportError:
                ISOLATED_LOGGER.warning("Cryptography not available in isolated process. Cannot use Fernet.")
            except Exception as e:
                ISOLATED_LOGGER.error(f"Failed to recreate Fernet instance in isolated process: {e}")

        _apply_posix_resource_limits(policy)
        _apply_windows_job_object_limits(policy)
        _apply_seccomp_filter(policy)
        plugin_module = importlib.import_module(plugin_module_name)
        plugin_class = getattr(plugin_module, class_name)
        # FIX: Pass fernet_instance to the plugin constructor
        plugin_instance = plugin_class(root, cache, policy, fernet_lib=fernet_instance)
        method = getattr(plugin_instance, method_name)
        # FIX: Use method_kwargs when calling the method
        result = asyncio.run(method(*args, **method_kwargs)) if asyncio.iscoroutinefunction(method) else method(*args, **method_kwargs)
        response_payload = {'is_exception': False, 'result': result}
    except Exception as e:
        ISOLATED_LOGGER.error(f"Error during isolated execution: {e}", exc_info=True)
        response_payload = {'is_exception': True, 'result': str(e)}
    json_response = json.dumps(response_payload).encode('utf-8')
    response_signature = hmac.new(ipc_key, json_response, hashlib.sha256).hexdigest()
    sys.stdout.buffer.write(response_signature.encode('utf-8') + b'|' + json_response)
    sys.stdout.flush()

if __name__ == "__main__":
    main()