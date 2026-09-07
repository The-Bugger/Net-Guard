# =============================================================================
# install.ps1 — NetGuard IDPS installer for Windows (PowerShell)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Installs Python deps into .venv\, initialises the database, and prints
# next steps. Packet capture requires Npcap: https://npcap.com/
# The prevention engine (iptables blocking) is Linux-only.
# =============================================================================

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

Write-Host "============================================" 
Write-Host "  NetGuard IDPS - Installer (Windows)"       
Write-Host "============================================" 
Write-Host ""

# ── Python detection ─────────────────────────────────────────────────────────
Write-Host "[1/6] Checking Python..."
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }

if (-not $py) {
    Write-Host "[!] Python 3.11+ not found. Install from https://python.org and re-run."
    exit 1
}

$pyCmd = $py.Source
$version = & $pyCmd --version 2>&1
$majorMinor = (& $pyCmd -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')") 2>$null
if ([version]$majorMinor -lt [version]"3.11") {
    Write-Host "[!] Python 3.11+ required (found ${version})."
    exit 1
}
Write-Host "  Python OK: ${version}"

# ── Npcap check (packet capture) ─────────────────────────────────────────────
Write-Host ""
Write-Host "[2/6] Checking Npcap (packet capture)..."
if (Test-Path "C:\Windows\System32\Npcap") {
    Write-Host "  Npcap: OK"
} else {
    Write-Host "  Npcap: not found - packet capture will be unavailable."
    Write-Host "  Install from https://npcap.com/ for live capture."
}

# ── Virtual environment ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/6] Creating virtual environment..."
if (-not (Test-Path "$ProjectDir\.venv")) {
    & $pyCmd -m venv "$ProjectDir\.venv"
}
$venvPython = "$ProjectDir\.venv\Scripts\python.exe"
Write-Host "  venv ready: $ProjectDir\.venv"

& $venvPython -m pip install --upgrade pip -q

# ── Python dependencies ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/6] Installing Python dependencies..."
& $venvPython -m pip install -r "$ProjectDir\requirements.txt" -q
Write-Host "  Dependencies installed."

# ── Environment config ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/6] Preparing environment config..."
if (-not (Test-Path "$ProjectDir\.env")) {
    Copy-Item "$ProjectDir\.env.example" "$ProjectDir\.env"
    Write-Host "  Created .env from template - edit SECRET_KEY before production."
} else {
    Write-Host "  .env exists - keeping it."
}

# ── Database ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] Initialising database..."
& $venvPython -c "from database.init_db import initialize_db; initialize_db(); print('  Database ready: database/netguard.db')"

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================"
Write-Host "  Install complete!"
Write-Host "============================================"
Write-Host ""
Write-Host "  Start (dev mode - detection/API, no firewall blocking):"
Write-Host "    .\.venv\Scripts\activate"
Write-Host "    python backend\main.py"
Write-Host ""
Write-Host "  Dashboard:  http://localhost:5000"
Write-Host "  Login:      admin / Admin@NetGuard1  (change immediately)"
Write-Host "  Tests:      pytest tests\ -q"
Write-Host ""
