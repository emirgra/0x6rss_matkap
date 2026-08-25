[CmdletBinding()]
param(
    [string]$JadxConfigDir = (Join-Path $env:APPDATA 'skylot\jadx\config')
)

$ErrorActionPreference = 'Stop'
$artifactName = 'matkap-jadx-connector-6.4.1.jar'
$repoArtifact = Join-Path $PSScriptRoot "dist\$artifactName"
$releaseArtifact = Join-Path $PSScriptRoot $artifactName
$artifact = if (Test-Path -LiteralPath $repoArtifact -PathType Leaf) { $repoArtifact } else { $releaseArtifact }
$expectedHash = '4C5505F089E686B04A9F8FC2EA778032C579D289A360D66466036718D48A7531'

Write-Host ''
Write-Host 'MATKAP JADX Connector' -ForegroundColor Cyan
Write-Host 'Installing the ready-to-use connector; no compilation is required.'
Write-Host ''

if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
    throw "Packaged JADX connector is missing: $artifact"
}
$actualHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw "Packaged JADX connector failed its SHA-256 integrity check. Expected $expectedHash but found $actualHash."
}

$pluginsDir = Join-Path $JadxConfigDir 'plugins'
$installedDir = Join-Path $pluginsDir 'installed'
$dropinsDir = Join-Path $pluginsDir 'dropins'
$existingPlugin = Join-Path $installedDir 'jadx-ai-mcp.jar'

New-Item -ItemType Directory -Path $installedDir -Force | Out-Null
New-Item -ItemType Directory -Path $dropinsDir -Force | Out-Null

if (Test-Path -LiteralPath $existingPlugin -PathType Leaf) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = "$existingPlugin.matkap-backup-$stamp"
    Copy-Item -LiteralPath $existingPlugin -Destination $backup
    Copy-Item -LiteralPath $artifact -Destination $existingPlugin -Force
    Write-Host "MATKAP JADX connector updated. Backup: $backup"
} else {
    $destination = Join-Path $dropinsDir $artifactName
    Copy-Item -LiteralPath $artifact -Destination $destination -Force
    Write-Host "MATKAP JADX connector installed: $destination"
}

$jadxRunning = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue | Where-Object {
    try { $_.Path -and $_.MainWindowTitle -match 'jadx' } catch { $false }
}
if ($jadxRunning) {
    Write-Warning 'Installation completed, but JADX is running. Close every JADX window and reopen JADX once.'
} else {
    Write-Host 'Installation completed successfully.' -ForegroundColor Green
    Write-Host 'Open JADX, load an APK, then open MATKAP MCP Lab and click Connect JADX.'
}

Write-Host 'Local connector address: http://127.0.0.1:8650'
