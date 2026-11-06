@echo off
setlocal EnableExtensions
rem ===========================================================
rem  WorkBuddy proxy - restart (LAN mode)
rem
rem  Stops whatever is serving the port, then launches
rem  start-wb-proxy-lan.bat so phones / other PCs can connect.
rem
rem  Usage: restart-wb-proxy.bat [port] [api-key]
rem         (both optional, forwarded to the LAN launcher)
rem
rem  Fixes over the old version:
rem   1. It stops the process that OWNS THE PORT, not only processes whose
rem      command line mentions wb_proxy.py. A gateway started by another
rem      shell can have an unreadable command line (seen 2026-11-06:
rem      pythonw 34128 listened on 8788 with a null CommandLine, the old
rem      filter matched nothing, then the launcher refused with
rem      "nothing was started - already running").
rem   2. The listen socket is found with RemotePort=0 rather than
rem      -State Listen: on this machine Get-NetTCPConnection reports a
rem      blank State, so -State Listen silently returns nothing.
rem   3. If the running gateway belongs to an elevated process, a normal
rem      shell gets "Access is denied". The script re-launches itself
rem      elevated instead of silently doing nothing.
rem
rem  ASCII-only on purpose: .bat files are parsed using the console code
rem  page, so non-ASCII text breaks the parser.
rem ===========================================================

set "PORT=%~1"
if "%PORT%"=="" set "PORT=8788"

echo Stopping whatever serves port %PORT% ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$port = [int]'%PORT%'; function Get-Owners($p) { try { Get-NetTCPConnection -LocalPort $p -ErrorAction Stop | Where-Object { $_.RemotePort -eq 0 -and $_.OwningProcess -gt 0 } | Select-Object -ExpandProperty OwningProcess } catch { @() } }; $ids = @(); $ids += (Get-Owners $port); $ids += (Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.Name -in @('python.exe','pythonw.exe') -and $_.CommandLine -like '*wb_proxy.py*' } | Select-Object -ExpandProperty ProcessId); $ids = $ids | Where-Object { $_ -and $_ -ne $PID } | Sort-Object -Unique; if (-not $ids) { Write-Host '  nothing is serving that port.' }; foreach ($id in $ids) { try { Stop-Process -Id $id -Force -ErrorAction Stop; Write-Host ('  stopped PID ' + $id) } catch { Write-Host ('  [WARN] cannot stop PID ' + $id + ': ' + $_.Exception.Message) } }; Start-Sleep -Milliseconds 900; $left = @(Get-Owners $port); if ($left.Count -gt 0) { Write-Host ('  [FAIL] port still in use by PID ' + ($left -join ',')); exit 2 } else { Write-Host '  port is free.' }"

if "%errorlevel%"=="2" goto elevate
goto launch

:elevate
echo.
echo This gateway was started with administrator rights, so a normal
echo shell cannot stop it. Re-launching this script elevated ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
echo If you declined the UAC prompt, the old gateway is still running.
exit /b 2

:launch
echo.
echo Starting LAN mode ...
call "%~dp0start-wb-proxy-lan.bat" %*
