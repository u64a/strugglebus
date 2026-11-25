@echo off
rem `wh`: the strugglebus worker host command. install.ps1 writes a copy of this file next to the
rem installed code with the full Python path and --home filled in; this one is for running from a clone.
setlocal
if defined WH_PYTHON (set "PY=%WH_PYTHON%") else (set "PY=python")
"%PY%" "%~dp0wh.py" %*
exit /b %ERRORLEVEL%
