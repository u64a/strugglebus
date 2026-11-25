"""Will Windows restart for updates at the nightly install time? (agent-host-build.md section 9.2)

setup\\20-policy makes Windows install updates daily at 03:00 and allows restarts only 02:00-08:00. The restart flag
appears only after the install, so the host also asks Windows Update's local cache (an offline search: no network,
a few seconds) whether updates that may need a restart are waiting.

Only Windows Update's own RebootRequired flag counts, not "Component Based Servicing\\RebootPending". Windows Update
restarts the machine in its window only for what IT installed. A CBS flag left by other servicing (an optional
feature, DISM) can sit there for days with no restart coming. On one host (the first night this guard ran
there) a CBS flag set since 15 Nov, with RebootRequired false and nothing waiting, made the host refuse every task
from 03:00 to 08:00, and would have done so from 21:00 every night after. Windows PowerShell 5.1 by full path runs the query:
the Windows Update COM API is there, and it works in the scheduled task's logon (a Store pwsh alias would not).
"""
from __future__ import annotations

import base64
import os
import subprocess

# Prints "<reboot flag 0|1> <waiting updates that may need a restart, or -1 if the search failed>".
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$reboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$n = 0
try {
    $q = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $q.Online = $false
    foreach ($u in $q.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates) {
        if ($u.InstallationBehavior.RebootBehavior -ne 0) { $n++ }
    }
} catch { $n = -1 }
'{0} {1}' -f [int]$reboot, $n
"""


def parse(out: str) -> bool | None:
    """True: a restart is expected (flag set, or updates that may restart are waiting); False: none expected;
    None: unknown (the search failed and no flag is set)."""
    try:
        flag, waiting = (int(x) for x in out.strip().split()[-2:])
    except ValueError:
        return None
    if flag:
        return True
    if waiting < 0:
        return None
    return waiting > 0


def restart_expected(run=subprocess.run, timeout: float = 120) -> bool | None:
    if os.name != "nt":
        return False
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")
    encoded = base64.b64encode(SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        r = run([exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], capture_output=True, text=True,
                timeout=timeout, stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse(r.stdout or "") if r.returncode == 0 else None
