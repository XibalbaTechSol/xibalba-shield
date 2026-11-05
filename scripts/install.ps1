# PowerShell installer for Xibalba Shield Windows Endpoint
$ErrorActionPreference = "Stop"
$backendUrl = if ($env:SHIELD_BACKEND_URL) { $env:SHIELD_BACKEND_URL } else { "https://xibalba-shield.onrender.com" }

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Installing Xibalba Shield Hybrid Protection Agent (Windows)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3 is required. Please install Python 3.12+ from python.org or the Microsoft Store."
    exit 1
}

Write-Host "Installing xibalba-shield package..." -ForegroundColor Yellow
pip install --upgrade git+https://github.com/XibalbaTechSol/xibalba-shield.git

Write-Host "Starting Shield setup and browser pairing..." -ForegroundColor Green
shield install --backend-url $backendUrl
