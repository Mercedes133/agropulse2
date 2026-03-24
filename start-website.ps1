$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$logsDir = Join-Path $projectRoot 'logs'
$stdoutLog = Join-Path $logsDir 'server.out.log'
$stderrLog = Join-Path $logsDir 'server.err.log'
$startupLog = Join-Path $logsDir 'startup.log'

New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

$nodePath = (Get-Command node -ErrorAction Stop).Source
$existingProcess = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" |
  Where-Object {
    $_.CommandLine -like '*server.js*' -and $_.CommandLine -like '*agric website*'
  } |
  Select-Object -First 1

if ($existingProcess) {
  Add-Content -Path $startupLog -Value "[$(Get-Date -Format s)] Server already running. PID=$($existingProcess.ProcessId)"
  exit 0
}

Add-Content -Path $startupLog -Value "[$(Get-Date -Format s)] Starting website server"

Start-Process `
  -FilePath $nodePath `
  -ArgumentList 'server.js' `
  -WorkingDirectory $projectRoot `
  -WindowStyle Hidden `
  -RedirectStandardOutput $stdoutLog `
  -RedirectStandardError $stderrLog
