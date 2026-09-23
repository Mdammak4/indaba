#!/usr/bin/env pwsh
# Simple test script - no emojis, just works!

Write-Host ""
Write-Host "============================================================"
Write-Host "  SENTINEL Defense - Simple Test"
Write-Host "============================================================"
Write-Host ""

# Check if defense server is running
Write-Host "Checking defense server..." -ForegroundColor Yellow
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8080/health" -Method GET -ErrorAction Stop -TimeoutSec 2
    Write-Host "SUCCESS: Defense server is running!" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Defense server not running!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Start the server first:" -ForegroundColor Yellow
    Write-Host "  cd starter-kits\python-defense"
    Write-Host "  python -m uvicorn app.main:app --host 127.0.0.1 --port 8080"
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Testing scenario: enterprise_memory_poison" -ForegroundColor Cyan
Write-Host "This is a memory poisoning attack scenario" -ForegroundColor Gray
Write-Host ""

# Run the test
$scenario = "scenarios/public/enterprise/enterprise_memory_poison.yaml"
uv run sentinel run --scenario $scenario --defense-url http://127.0.0.1:8080

Write-Host ""
Write-Host "============================================================"
Write-Host "  Test Complete!"
Write-Host "============================================================"
Write-Host ""
Write-Host "Check your results:" -ForegroundColor Cyan
Write-Host "  1. Terminal 1 (defense): See Tagger analysis output"
Write-Host "  2. Above: See attack success/failure results"
Write-Host "  3. artifacts/ folder: See detailed logs"
Write-Host ""
