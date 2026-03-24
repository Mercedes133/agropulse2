$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $projectRoot 'start-website.ps1'
$startupFolder = [Environment]::GetFolderPath('Startup')
$launcherPath = Join-Path $startupFolder 'AgroPluseServer.vbs'

$escapedScriptPath = $scriptPath.Replace('"', '""')
$launcherContent = @"
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$escapedScriptPath""", 0, False
"@

Set-Content -Path $launcherPath -Value $launcherContent -Encoding ASCII

Write-Output "Startup launcher created at $launcherPath"