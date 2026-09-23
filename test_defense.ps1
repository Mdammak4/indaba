#!/usr/bin/env pwsh
# Quick test script for SENTINEL defense

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          SENTINEL Defense - Quick Test                      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if defense server is running
Write-Host "🔍 Checking if defense server is running..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8080/health" -Method GET -ErrorAction SilentlyContinue -TimeoutSec 2
    Write-Host "✅ Defense server is running!" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "❌ Defense server not running!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please start the server first:" -ForegroundColor Yellow
    Write-Host "  cd starter-kits\python-defense" -ForegroundColor White
    Write-Host "  python -m uvicorn app.main:app --host 127.0.0.1 --port 8080" -ForegroundColor White
    Write-Host ""
    exit 1
}

# Default to memory poison scenario
$scenario = "scenarios/public/enterprise/enterprise_memory_poison.yaml"

Write-Host "🎯 Testing scenario: enterprise_memory_poison" -ForegroundColor Cyan
Write-Host "   This is a memory poisoning attack - should show HIGH/CRITICAL risk" -ForegroundColor Gray
Write-Host ""

Write-Host "🚀 Running test..." -ForegroundColor Yellow
Write-Host ""

# Run the scenario
uv run sentinel run --scenario $scenario --defense-url http://127.0.0.1:8080

Write-Host ""
Write-Host "✅ Test complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Check the results:" -ForegroundColor Cyan
Write-Host "   • Terminal 1 (defense server): See Tagger analysis" -ForegroundColor Gray
Write-Host "   • Above output: See attack success/failure" -ForegroundColor Gray
Write-Host "   • artifacts/ folder: See detailed logs" -ForegroundColor Gray
Write-Host ""
