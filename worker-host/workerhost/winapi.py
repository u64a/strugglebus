"""Windows APIs through ctypes: DPAPI, Job Objects, a named mutex, memory, processes, boot time.

On other platforms (CI never runs there, but imports must not fail) the functions raise
NotImplementedError or return neutral values, so pure logic stays importable and testable.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import time
from ctypes import wintypes

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")

    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetSystemTimes.argtypes = [ctypes.POINTER(wintypes.FILETIME)] * 3
    kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
STILL_ACTIVE = 259
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9
ERROR_ALREADY_EXISTS = 183
CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise NotImplementedError("Windows only")


# --- DPAPI (current user) -----------------------------------------------------------------------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


_ENTROPY = b"strugglebus-worker-host/v1"


def _blob(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_protect(data: bytes, description: str = "strugglebus-worker-host") -> bytes:
    _require_windows()
    src, _keep1 = _blob(data)
    ent, _keep2 = _blob(_ENTROPY)
    out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(src), description, ctypes.byref(ent), None, None,
                                    CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise OSError(ctypes.get_last_error(), "CryptProtectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, wintypes.HLOCAL))


def dpapi_unprotect(data: bytes) -> bytes:
    _require_windows()
    src, _keep1 = _blob(data)
    ent, _keep2 = _blob(_ENTROPY)
    out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent), None, None,
                                      CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, wintypes.HLOCAL))


# --- Job Objects --------------------------------------------------------------------------------

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class Job:
    """A kill-on-close Job Object: closing the host's handle (or the host dying) ends every worker."""

    def __init__(self):
        _require_windows()
        self.handle = kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObject failed")
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(self.handle, JobObjectExtendedLimitInformation, ctypes.byref(info),
                                                ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")

    def assign(self, proc: subprocess.Popen) -> None:
        if not kernel32.AssignProcessToJobObject(self.handle, int(proc._handle)):  # noqa: SLF001
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")

    def terminate(self, code: int = 1) -> None:
        if self.handle:
            kernel32.TerminateJobObject(self.handle, code)

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None


def start_in_job(cmd: list[str], job: Job, **popen_kwargs) -> subprocess.Popen:
    """Start suspended, put it in the job, then resume, so no child escapes before assignment."""
    _require_windows()
    flags = popen_kwargs.pop("creationflags", 0) | CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    proc = subprocess.Popen(cmd, creationflags=flags, **popen_kwargs)
    try:
        job.assign(proc)
    except OSError:
        proc.kill()
        raise
    status = ntdll.NtResumeProcess(int(proc._handle))  # noqa: SLF001
    if status != 0:
        job.terminate()
        raise OSError(status, "NtResumeProcess failed")
    return proc


# --- single instance ----------------------------------------------------------------------------

def single_instance(name: str):
    """Return a mutex handle, or None if another host process already holds it."""
    _require_windows()
    handle = kernel32.CreateMutexW(None, True, name)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateMutex failed")
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    return handle


# --- memory and processes -----------------------------------------------------------------------

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD), ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def memory() -> dict:
    """Commit limit and committed bytes (as Win32_OperatingSystem's virtual memory figures), free RAM."""
    _require_windows()
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(st)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        raise OSError(ctypes.get_last_error(), "GlobalMemoryStatusEx failed")
    return {"commit_limit": st.ullTotalPageFile, "committed": st.ullTotalPageFile - st.ullAvailPageFile,
            "free_phys": st.ullAvailPhys, "total_phys": st.ullTotalPhys}


def system_times() -> tuple[int, int, int]:
    """(idle, kernel, user) CPU time across all processors, in 100 ns units (GetSystemTimes; kernel includes idle).
    Two readings give the busy share in between: see cpu_busy_pct."""
    _require_windows()
    idle, kern, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
    if not kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)):
        raise OSError(ctypes.get_last_error(), "GetSystemTimes failed")
    as_int = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    return as_int(idle), as_int(kern), as_int(user)


def cpu_busy_pct(before: tuple[int, int, int], after: tuple[int, int, int]) -> float | None:
    """The share of CPU time spent busy between two system_times() readings, 0-100; None if no time passed."""
    idle = after[0] - before[0]
    total = (after[1] - before[1]) + (after[2] - before[2])
    if total <= 0:
        return None
    return max(0.0, min(100.0, 100.0 * (total - idle) / total))


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


def process_names() -> set[str]:
    """Lower-case image names of every running process."""
    if not IS_WINDOWS:
        return set()
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return set()
    names: set[str] = set()
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            names.add(entry.szExeFile.lower())
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return names


def boot_time() -> float:
    """Epoch seconds of the last boot."""
    if not IS_WINDOWS:
        return 0.0
    return time.time() - kernel32.GetTickCount64() / 1000.0


def _filetime_to_int(ft: wintypes.FILETIME) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def process_identity(pid: int) -> int | None:
    """Creation time of a live process (guards against pid reuse), or None if it is gone."""
    if not IS_WINDOWS or pid <= 0:
        return None
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(h, ctypes.byref(code)) or code.value != STILL_ACTIVE:
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(h, *(ctypes.byref(t) for t in times)):
            return None
        return _filetime_to_int(times[0])
    finally:
        kernel32.CloseHandle(h)


ERROR_ACCESS_DENIED = 5


def pid_alive(pid: int) -> bool:
    """Does a process with this pid exist? Unlike process_identity, a process we may not open counts as alive.

    The host runs in session 0 under its scheduled task (Password logon). Its process DACL admits that logon session
    and full administrator tokens only, so the status window and `wh` in the signed-in, non-elevated session get
    ERROR_ACCESS_DENIED for a host that is running (the window once said "Not running"). A pid that is
    gone gives ERROR_INVALID_PARAMETER instead. Callers pair this with status.json being fresh, which also covers
    pid reuse."""
    if not IS_WINDOWS or pid <= 0:
        return False
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        code = wintypes.DWORD()
        return not kernel32.GetExitCodeProcess(h, ctypes.byref(code)) or code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(h)


def terminate_pid(pid: int, code: int = 1) -> bool:
    if not IS_WINDOWS or pid <= 0:
        return False
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    try:
        return bool(kernel32.TerminateProcess(h, code))
    finally:
        kernel32.CloseHandle(h)
