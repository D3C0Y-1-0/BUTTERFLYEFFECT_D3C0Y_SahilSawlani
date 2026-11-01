# ATHENA - one-command launcher (Windows PowerShell). Restarts the server by itself if it ever exits.
# First run: finds a suitable Python (3.11 - 3.13, 64-bit), builds .venv, installs packages (wheels only, nothing is compiled), builds the UI, starts the server.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-Python($exe, $extra) {
  try {
    $out = & $exe @extra -c "import sys; print('%d.%d.%d' % sys.version_info[:3] + ' ' + ('64' if sys.maxsize > 2**32 else '32'))" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $p = ($out | Select-Object -First 1).ToString().Split(" ")
    $v = [version]$p[0]
    if ($p[1] -eq "64" -and $v.Major -eq 3 -and $v.Minor -ge 11 -and $v.Minor -le 13) { return $p[0] }
  } catch {}
  return $null
}

function Find-Python {
  foreach ($v in @("3.12", "3.11", "3.13")) {
    if (Get-Command py -ErrorAction SilentlyContinue) { if (Test-Python "py" @("-$v")) { return @("py", "-$v") } }
  }
  foreach ($n in @("python", "python3")) {
    if (Get-Command $n -ErrorAction SilentlyContinue) { if (Test-Python $n @()) { return @($n) } }
  }
  return $null
}

$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$needInstall = $true
if (Test-Path $venvPy) {
  & $venvPy -c "import uvicorn, fastapi, numpy, wntr, pandapower, ortools, sklearn" 2>$null
  if ($LASTEXITCODE -eq 0) { $needInstall = $false } else { Write-Host "The .venv folder is incomplete (an earlier install failed). Rebuilding it." -ForegroundColor Yellow; Remove-Item -Recurse -Force .venv }
}
if ($needInstall) {
  $py = Find-Python
  if (-not $py) {
    Write-Host ""
    Write-Host "ATHENA needs 64-bit Python 3.11, 3.12 or 3.13. It was not found (or only a 32-bit / newer / older version is installed)." -ForegroundColor Red
    Write-Host "Install one, then run .\run.ps1 again:" -ForegroundColor Yellow
    Write-Host "    winget install Python.Python.3.12        (or download the 64-bit installer from https://www.python.org/downloads/)" -ForegroundColor Yellow
    exit 1
  }
  Write-Host ("Using Python: " + ($py -join " ")) -ForegroundColor Cyan
  $exe = $py[0]; $rest = @(); if ($py.Count -gt 1) { $rest = $py[1..($py.Count - 1)] }
  & $exe @rest -m venv .venv
  if ($LASTEXITCODE -ne 0) { Write-Host "Could not create the virtual environment." -ForegroundColor Red; exit 1 }
  & $venvPy -m pip install --upgrade pip
  Write-Host "Installing packages (first time only, a few minutes)..." -ForegroundColor Cyan
  & $venvPy -m pip install --only-binary=:all: -r requirements.txt
  if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Package install failed. Nothing is compiled by this script, so the usual cause is a Python version without ready-made packages." -ForegroundColor Red
    Write-Host "Use 64-bit Python 3.11 or 3.12, delete the .venv folder, and run .\run.ps1 again." -ForegroundColor Yellow
    Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue
    exit 1
  }
}

# The interface is rebuilt whenever the build is missing, half-finished (no index.html, for example after an interrupted build) or older than the source files.
# Before this check, a friend with a leftover frontend\dist folder had to delete it by hand.
$distIndex = "frontend\dist\index.html"
$srcNewest = Get-ChildItem frontend\src, frontend\index.html, frontend\public, frontend\package.json -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$needBuild = (-not (Test-Path $distIndex)) -or (-not (Test-Path "frontend\dist\assets")) -or ($srcNewest -and $srcNewest.LastWriteTime -gt (Get-Item $distIndex).LastWriteTime)
if ($needBuild) {
  if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Write-Host "Node.js is needed once to build the interface. Install it from https://nodejs.org (LTS) and run .\run.ps1 again." -ForegroundColor Red; exit 1 }
  Write-Host "Building the interface (first run, or the code changed)..." -ForegroundColor Cyan
  Remove-Item -Recurse -Force frontend\dist -ErrorAction SilentlyContinue
  Push-Location frontend
  if (-not (Test-Path node_modules\vite)) { npm install; if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "npm install failed (see above)." -ForegroundColor Red; exit 1 } }
  npm run build
  $buildCode = $LASTEXITCODE
  Pop-Location
  if ($buildCode -ne 0 -or -not (Test-Path $distIndex)) { Remove-Item -Recurse -Force frontend\dist -ErrorAction SilentlyContinue; Write-Host "The interface build failed (see the messages above). The half-built folder was removed; fix the error and run .\run.ps1 again." -ForegroundColor Red; exit 1 }
}
$env:DECOY_DEMO = "1"          # shows demo accounts + live TOTP codes on the login page. Set to 0 in production.
$env:PYTHONWARNINGS = "ignore"

# Clicking inside a Windows console freezes the program until a key is pressed ("QuickEdit"). Switch that off for this window.
try {
  Add-Type -Namespace Win -Name Con -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int h);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(System.IntPtr h, out uint m);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(System.IntPtr h, uint m);
'@
  $h = [Win.Con]::GetStdHandle(-10); $m = 0
  if ([Win.Con]::GetConsoleMode($h, [ref]$m)) { [void][Win.Con]::SetConsoleMode($h, ($m -band (-bnot 0x40)) -bor 0x80) }
} catch {}

$busy = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($busy) {
  Write-Host "Port 8000 is already used by process $($busy.OwningProcess) (probably an older ATHENA server)." -ForegroundColor Yellow
  Write-Host "Stop it with:  Stop-Process -Id $($busy.OwningProcess) -Force    then run .\run.ps1 again." -ForegroundColor Yellow
  exit 1
}
Write-Host "ATHENA -> http://127.0.0.1:8000   (first start: ~10 s boot, ~30 s until risk analytics are ready)"
Push-Location backend
$ErrorActionPreference = "Continue"
$fails = 0
while ($true) {
  $t0 = Get-Date
  ..\.venv\Scripts\python -m uvicorn decoy.api:app --host 127.0.0.1 --port 8000 --log-level warning
  if (((Get-Date) - $t0).TotalSeconds -lt 15) { $fails++ } else { $fails = 0 }
  if ($fails -ge 3) { Write-Host "The server keeps stopping right after it starts. Read the error above; run .\run.ps1 again after fixing it." -ForegroundColor Red; exit 1 }
  Write-Host "Server stopped (exit $LASTEXITCODE). Restarting in 2 s - press Ctrl+C to quit." -ForegroundColor Yellow
  Start-Sleep -Seconds 2
}
