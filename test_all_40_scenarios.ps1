# Test ALL 40 YAML scenarios against your defense
# Make sure your defense is running on http://127.0.0.1:8080 first!

Write-Host "=" * 80
Write-Host "TESTING ALL 40 SCENARIOS WITH YOUR DEFENSE"
Write-Host "=" * 80
Write-Host ""

# Check if defense is running
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8080/healthz" -UseBasicParsing -ErrorAction Stop
    Write-Host "✅ Defense service is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Defense service is NOT running!" -ForegroundColor Red
    Write-Host "Please start it first:"
    Write-Host "  cd starter-kits/python-defense"
    Write-Host "  python -m uvicorn app.main:app --host 127.0.0.1 --port 8080"
    exit 1
}

Write-Host ""

# Get all scenarios
$scenarios = Get-ChildItem -Path scenarios/public -Recurse -Filter *.yaml | ForEach-Object { $_.FullName }

Write-Host "Found $($scenarios.Count) scenarios"
Write-Host ""

$results = @()
$counter = 0

foreach ($scenarioPath in $scenarios) {
    $counter++
    $name = Split-Path $scenarioPath -Leaf
    $domain = (Split-Path (Split-Path $scenarioPath -Parent) -Leaf)
    
    Write-Host "[$counter/$($scenarios.Count)] Testing: " -NoNewline
    Write-Host "$domain/$name" -ForegroundColor Cyan
    
    try {
        # Run the scenario (suppress most output)
        $output = uv run sentinel run --scenario $scenarioPath --defense-url http://127.0.0.1:8080 2>&1 | Out-String
        
        if ($LASTEXITCODE -eq 0) {
            # Parse results
            $attack_present = if ($output -match "attack_present=(\w+)") { $matches[1] } else { "?" }
            $attack_success = if ($output -match "attack_success=(\w+)") { $matches[1] } else { "?" }
            $task_success = if ($output -match "task_success=(\w+)") { $matches[1] } else { "?" }
            $critical_violation = if ($output -match "critical_violation=(\w+)") { $matches[1] } else { "?" }
            $steps = if ($output -match "steps=(\d+)") { $matches[1] } else { "?" }
            
            # Determine status
            $attackBlocked = if ($attack_present -eq "True") {
                if ($attack_success -eq "False") { "✅" } else { "❌" }
            } else {
                "-"  # No attack in this scenario
            }
            
            $taskCompleted = if ($task_success -eq "True") { "✅" } else { "❌" }
            
            $results += [PSCustomObject]@{
                Domain = $domain
                Scenario = $name
                AttackPresent = $attack_present
                AttackBlocked = $attackBlocked
                TaskCompleted = $taskCompleted
                CriticalViolation = $critical_violation
                Steps = $steps
                Status = "OK"
            }
            
            Write-Host "  Attack: $attack_present | Blocked: $attackBlocked | Task: $taskCompleted | Steps: $steps"
        } else {
            $results += [PSCustomObject]@{
                Domain = $domain
                Scenario = $name
                AttackPresent = "?"
                AttackBlocked = "?"
                TaskCompleted = "?"
                CriticalViolation = "?"
                Steps = "?"
                Status = "ERROR"
            }
            Write-Host "  ERROR running scenario" -ForegroundColor Red
        }
    } catch {
        Write-Host "  EXCEPTION: $_" -ForegroundColor Red
    }
    
    Write-Host ""
}

# ============================================================================
# DETAILED SUMMARY
# ============================================================================

Write-Host ""
Write-Host "=" * 80
Write-Host "DETAILED RESULTS"
Write-Host "=" * 80
Write-Host ""

# Group by domain
$domains = $results | Group-Object -Property Domain

foreach ($domainGroup in $domains) {
    Write-Host ""
    $domainName = $domainGroup.Name.ToUpper()
    $scenarioCount = $domainGroup.Count
    Write-Host "DOMAIN: $domainName ($scenarioCount scenarios)" -ForegroundColor Yellow
    Write-Host ("-" * 80)
    
    $domainGroup.Group | Format-Table -Property Scenario, AttackPresent, AttackBlocked, TaskCompleted, Steps -AutoSize
}

# ============================================================================
# STATISTICS
# ============================================================================

Write-Host ""
Write-Host "=" * 80
Write-Host "STATISTICS"
Write-Host "=" * 80

$totalScenarios = $results.Count
$attackScenarios = ($results | Where-Object { $_.AttackPresent -eq "True" }).Count
$benignScenarios = $totalScenarios - $attackScenarios

$attacksBlocked = ($results | Where-Object { $_.AttackBlocked -eq "✅" }).Count
$attacksPassed = ($results | Where-Object { $_.AttackBlocked -eq "❌" }).Count

$tasksCompleted = ($results | Where-Object { $_.TaskCompleted -eq "✅" }).Count
$tasksFailed = ($results | Where-Object { $_.TaskCompleted -eq "❌" }).Count

$errors = ($results | Where-Object { $_.Status -eq "ERROR" }).Count

Write-Host ""
Write-Host "[Overall Statistics]"
Write-Host "   Total scenarios: $totalScenarios"
Write-Host "   Attack scenarios: $attackScenarios"
Write-Host "   Benign scenarios: $benignScenarios"
Write-Host "   Errors: $errors"

Write-Host ""
Write-Host "[Attack Defense]"
Write-Host "   Attacks blocked: $attacksBlocked / $attackScenarios" -NoNewline
$blockRate = if ($attackScenarios -gt 0) { [math]::Round(($attacksBlocked / $attackScenarios) * 100, 1) } else { 0 }
Write-Host " ($blockRate%)" -ForegroundColor $(if ($blockRate -ge 70) { "Green" } elseif ($blockRate -ge 40) { "Yellow" } else { "Red" })

Write-Host "   Attacks succeeded: $attacksPassed / $attackScenarios" -NoNewline
$passRate = if ($attackScenarios -gt 0) { [math]::Round(($attacksPassed / $attackScenarios) * 100, 1) } else { 0 }
Write-Host " ($passRate%)" -ForegroundColor $(if ($passRate -le 30) { "Green" } elseif ($passRate -le 60) { "Yellow" } else { "Red" })

Write-Host ""
Write-Host "[Task Completion]"
Write-Host "   Tasks completed: $tasksCompleted / $totalScenarios" -NoNewline
$taskRate = [math]::Round(($tasksCompleted / $totalScenarios) * 100, 1)
Write-Host " ($taskRate%)" -ForegroundColor $(if ($taskRate -ge 70) { "Green" } elseif ($taskRate -ge 40) { "Yellow" } else { "Red" })

Write-Host "   Tasks failed: $tasksFailed / $totalScenarios"

# ============================================================================
# INTERPRETATION
# ============================================================================

Write-Host ""
Write-Host "=" * 80
Write-Host "INTERPRETATION"
Write-Host "=" * 80
Write-Host ""
Write-Host "Legend:"
Write-Host "  ✅ Attack blocked = Defense stopped the attack (attack_success=False)"
Write-Host "  ❌ Attack succeeded = Attack got through (attack_success=True)"
Write-Host "  ✅ Task completed = Benign work finished (task_success=True)"
Write-Host "  ❌ Task failed = Legitimate work blocked (task_success=False)"
Write-Host "  -  = No attack in this scenario (benign test)"
Write-Host ""
Write-Host "Goal:"
Write-Host "  • High 'Attacks blocked' % = Good defense 🛡️"
Write-Host "  • High 'Tasks completed' % = Agent stays useful ⚡"
Write-Host "  • Best: Block attacks AND complete tasks!"
Write-Host ""

# ============================================================================
# PROBLEM SCENARIOS
# ============================================================================

$problemScenarios = $results | Where-Object { 
    $_.AttackBlocked -eq "❌" -or 
    ($_.TaskCompleted -eq "❌" -and $_.AttackPresent -eq "False") -or
    $_.Status -eq "ERROR"
}

if ($problemScenarios.Count -gt 0) {
    Write-Host ""
    Write-Host "=" * 80
    Write-Host "PROBLEM SCENARIOS ($($problemScenarios.Count) need attention)" -ForegroundColor Yellow
    Write-Host "=" * 80
    Write-Host ""
    
    $problemScenarios | Format-Table -Property Domain, Scenario, AttackBlocked, TaskCompleted, Status -AutoSize
    
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "   1. Focus on scenarios where attacks succeeded (X in AttackBlocked)"
    Write-Host "   2. Build C1 (Authority), C2 (Policy), C3 (Content) to block them"
    Write-Host "   3. Check scenarios where tasks failed unnecessarily"
}

# ============================================================================
# SAVE RESULTS
# ============================================================================

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = "test_results_$timestamp.csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation

Write-Host ""
Write-Host "=" * 80
Write-Host "Results saved to: $reportPath"
Write-Host "=" * 80
