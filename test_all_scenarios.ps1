# Test all YAML scenarios against your defense
# Make sure your defense is running on http://127.0.0.1:8080 first!

Write-Host "=" * 70
Write-Host "TESTING ALL SCENARIOS WITH YOUR DEFENSE"
Write-Host "=" * 70

$scenarios = @(
    # Finance scenarios
    "scenarios/public/finance/finance_false_approval.yaml",
    "scenarios/public/finance/finance_refund_confirmed.yaml",
    "scenarios/public/finance/finance_direct_transfer.yaml",
    
    # SOC scenarios
    "scenarios/public/soc/soc_backup_token_disclosure.yaml",
    "scenarios/public/soc/soc_hostile_log_text.yaml",
    "scenarios/public/soc/soc_direct_monitoring_off.yaml",
    
    # Enterprise scenarios
    "scenarios/public/enterprise/enterprise_memory_poison.yaml",
    "scenarios/public/enterprise/enterprise_poisoned_invoice.yaml",
    "scenarios/public/enterprise/enterprise_direct_token_request.yaml"
)

$results = @()

foreach ($scenario in $scenarios) {
    $name = Split-Path $scenario -Leaf
    Write-Host "`n" + ("=" * 70)
    Write-Host "Testing: $name"
    Write-Host ("=" * 70)
    
    try {
        # Run the scenario
        $output = uv run sentinel run --scenario $scenario --defense-url http://127.0.0.1:8080 2>&1
        
        # Check if it succeeded
        if ($LASTEXITCODE -eq 0) {
            # Parse results
            $attack_success = $output | Select-String "attack_success=(\w+)" | ForEach-Object { $_.Matches.Groups[1].Value }
            $task_success = $output | Select-String "task_success=(\w+)" | ForEach-Object { $_.Matches.Groups[1].Value }
            
            $results += [PSCustomObject]@{
                Scenario = $name
                AttackBlocked = if ($attack_success -eq "False") { "✅" } else { "❌" }
                TaskCompleted = if ($task_success -eq "True") { "✅" } else { "❌" }
                Status = "OK"
            }
            
            Write-Host "  Attack blocked: $attack_success"
            Write-Host "  Task completed: $task_success"
        } else {
            $results += [PSCustomObject]@{
                Scenario = $name
                AttackBlocked = "?"
                TaskCompleted = "?"
                Status = "ERROR"
            }
            Write-Host "  ERROR running scenario"
        }
    } catch {
        Write-Host "  EXCEPTION: $_"
    }
}

# Summary
Write-Host "`n" + ("=" * 70)
Write-Host "SUMMARY"
Write-Host ("=" * 70)

$results | Format-Table -AutoSize

Write-Host "`nInterpretation:"
Write-Host "  ✅ Attack blocked = defense stopped the attack"
Write-Host "  ✅ Task completed = benign work still works"
Write-Host "  Best result: Attack blocked ✅ AND Task completed ✅"
