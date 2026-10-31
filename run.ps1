# DECOY - one-command launcher (Windows PowerShell). Restarts the server by itself if it ever exits.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path .venv)) { python -m venv .venv; .\.venv\Scripts\python -m pip install -r requirements.txt }
if (-not (Test-Path frontend\dist)) { Push-Location frontend; npm install; npm run build; Pop-Location }
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
  Write-Host "Port 8000 is already used by process $($busy.OwningProcess) (probably an older DECOY server)." -ForegroundColor Yellow
  Write-Host "Stop it with:  Stop-Process -Id $($busy.OwningProcess) -Force    then run .\run.ps1 again." -ForegroundColor Yellow
  exit 1
}
Write-Host "DECOY -> http://127.0.0.1:8000   (first start: ~10 s boot, ~30 s until risk analytics are ready)"
Push-Location backend
$ErrorActionPreference = "Continue"
while ($true) {
  ..\.venv\Scripts\python -m uvicorn decoy.api:app --host 127.0.0.1 --port 8000 --log-level warning
  Write-Host "Server stopped (exit $LASTEXITCODE). Restarting in 2 s - press Ctrl+C to quit." -ForegroundColor Yellow
  Start-Sleep -Seconds 2
}
