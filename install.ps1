# Windows installer: builds iitg-connect and installs iitg-connect / iitg-stop /
# iitg-update / iitg-status into %LOCALAPPDATA%\Programs\iitg-connect, added to your PATH.
$ErrorActionPreference = 'Stop'
$BinDir = if ($env:BIN_DIR) { $env:BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\iitg-connect' }
Set-Location $PSScriptRoot

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host 'Rust is not installed. Install it from https://rustup.rs and run this again.' -ForegroundColor Red
    exit 1
}

cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
try {
    Copy-Item 'target\release\iitg-connect.exe' $BinDir -Force
} catch {
    Write-Host 'iitg-connect is running, so it cannot be replaced. Run iitg-stop, then run this again.' -ForegroundColor Red
    exit 1
}
# Small launchers so the other commands work from cmd and PowerShell alike.
foreach ($cmd in 'stop', 'update', 'status') {
    Set-Content -Path (Join-Path $BinDir "iitg-$cmd.cmd") -Value "@`"%~dp0iitg-connect.exe`" $cmd %*" -Encoding Ascii
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $BinDir) {
    $newPath = if ($userPath) { "$userPath;$BinDir" } else { $BinDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "Added $BinDir to your PATH. Open a new terminal to use the commands."
}
Write-Host "Installed to ${BinDir}: iitg-connect, iitg-stop, iitg-update, iitg-status" -ForegroundColor Green
