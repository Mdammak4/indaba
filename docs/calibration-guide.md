# Tagger Calibration Guide
## Validating Component A Risk Scores Against Ground Truth

---

## Overview

**Calibration** is the process of comparing your Tagger's predicted risk scores against SENTINEL's ground truth outcomes to validate that your scoring system accurately identifies threats.

### Why Calibration Matters

1. **Validates scoring weights**: Confirms your trust/action/sensitivity weights are correct
2. **Tunes thresholds**: Helps adjust SAFE/LOW/MODERATE/HIGH/CRITICAL boundaries
3. **Identifies blind spots**: Shows which attack patterns you're missing
4. **Provides metrics**: Gives you precision/recall/F1 scores for your technical report
5. **Required for submission**: Jury wants to see evidence your system works

---

## The Calibration Process

### Step 1: Run Scenarios Against Your Defense

Start your defense server:
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Run test scenarios (in a new terminal):
```powershell
# Single scenario
uv run sentinel run --scenario scenarios/public/enterprise/enterprise_memory_poison.yaml --defense-url http://127.0.0.1:8080

# All 40 scenarios
.\test_all_40_scenarios.ps1
```

This creates artifacts in `artifacts/eval-run-*/` containing:
- `*.jsonl` - Step-by-step logs with your defense decisions
- `*.summary.json` - Ground truth outcomes (attack_success, violations, etc.)

### Step 2: Extract Actual Tagger Scores

Run the extraction script:
```powershell
python extract_actual_tagger_scores.py
```

This parses the `.jsonl` files and extracts the `risk_score` from each defense decision.

**Output**: `tagger_scores.json` containing:
```json
{
  "enterprise_memory_poison": {
    "avg_risk_score": 68.5,
    "max_risk_score": 85.2,
    "critical_steps": 3,
    "high_steps": 5,
    ...
  }
}
```

### Step 3: Run Calibration Analysis

Compare Tagger predictions vs ground truth:
```powershell
python calibration_system.py
```

**Outputs**:
- **Console report**: Summary statistics, domain breakdown, recommendations
- **calibration_results.csv**: Detailed per-scenario comparison for Excel/analysis

---

## Understanding the Metrics

### Prediction Accuracy

| Metric | Meaning | What You Want |
|--------|---------|---------------|
| **TP (True Positive)** | Attack present, Tagger flagged HIGH/CRITICAL | Maximize this |
| **TN (True Negative)** | Safe scenario, Tagger scored LOW/SAFE | Maximize this |
| **FP (False Positive)** | Safe scenario, Tagger flagged HIGH/CRITICAL | Minimize (false alarms) |
| **FN (False Negative)** | Attack present, Tagger scored LOW/SAFE | Minimize (missed threats) |

### Derived Metrics

```
Precision = TP / (TP + FP)
  → When you predict "attack", how often are you correct?
  → Target: 70-85% (balance safety with usability)

Recall = TP / (TP + FN)
  → What % of actual attacks do you detect?
  → Target: 80-95% (catch most threats)

F1 Score = 2 × (Precision × Recall) / (Precision + Recall)
  → Harmonic mean balancing both
  → Target: 75-90%
```

### Severity Matching

Compares your risk classification vs what actually happened:

- **Matches**: Your severity prediction was correct (e.g., CRITICAL for critical_violation)
- **Overestimate**: You flagged safe scenarios as dangerous (FP)
- **Underestimate**: You missed dangerous scenarios (FN)

---

## Example Calibration Report

```
TAGGER CALIBRATION REPORT
================================================================================
📊 SUMMARY STATISTICS
Total Scenarios:        40
True Positives (TP):    28  (Attack detected correctly)
True Negatives (TN):     8  (Safe scenario, low risk)
False Positives (FP):    2  (Safe scenario, high risk)
False Negatives (FN):    2  (Attack missed)

Precision:              93.33%  (When we predict attack, correct rate)
Recall:                 93.33%  (Attack detection rate)
F1 Score:               93.33%  (Harmonic mean)

Severity Calibration:
  Matches:               32  (80.0%)
  Overestimates:          6  (15.0%)
  Underestimates:         2  (5.0%)

📂 BY DOMAIN
ENTERPRISE   | Count: 15 | TP:12 TN:2 FP:0 FN:1 | Avg Risk:  65.3
FINANCE      | Count: 13 | TP: 9 TN:3 FP:1 FN:0 | Avg Risk:  58.7
SOC          | Count: 12 | TP: 7 TN:3 FP:1 FN:1 | Avg Risk:  62.1

⚡ DIFFICULTY CORRELATION
Difficulty 1 | Count: 10 | Avg Risk:  42.5
Difficulty 2 | Count: 12 | Avg Risk:  58.3
Difficulty 3 | Count:  9 | Avg Risk:  67.8
Difficulty 4 | Count:  6 | Avg Risk:  75.2
Difficulty 5 | Count:  3 | Avg Risk:  82.1
```

---

## Tuning Based on Results

### High False Positives (FP)

**Problem**: Safe scenarios getting HIGH/CRITICAL scores

**Solutions**:
1. Reduce sensitivity weights for read-only actions
2. Increase SAFE threshold from 15 to 20
3. Lower trust penalty for `user_controlled` sources
4. Add more benign patterns to safe list

**Example**:
```python
# In tagger.py
SENSITIVITY_WEIGHTS = {
    'public': 0.8,        # Was 1.0 - reduced to avoid FP
    'internal': 1.3,      # Was 1.5
    'confidential': 2.0,  # Was 2.5
    'restricted': 2.5     # Was 3.0
}
```

### High False Negatives (FN)

**Problem**: Attacks being missed (scored too low)

**Solutions**:
1. Increase sensitivity detection (more secret patterns)
2. Lower CRITICAL threshold from 76 to 70
3. Increase weight for `write_irreversible` actions
4. Add provenance tracking for memory poisoning

**Example**:
```python
# In tagger.py
ACTION_WEIGHTS = {
    'read': 0.15,                    # Was 0.1
    'write_reversible': 0.4,         # Was 0.35
    'write_irreversible': 0.75,      # Was 0.65
    'delete_recoverable': 0.7,       # Was 0.6
    'delete_permanent': 0.95         # Unchanged
}
```

### Poor Difficulty Correlation

**Problem**: High-difficulty attacks not scoring higher than low-difficulty

**Solutions**:
1. Add difficulty-based multiplier in risk calculation
2. Improve complex attack pattern detection
3. Track multi-step attack chains

---

## Integration with Technical Report

### Metrics to Include

1. **Overall Performance**:
   - Precision: X%
   - Recall: Y%
   - F1 Score: Z%

2. **Domain Breakdown**:
   - Table showing TP/TN/FP/FN per domain
   - Attack family detection rates

3. **Visualization**:
   - Confusion matrix (TP/TN/FP/FN)
   - Risk score distribution histogram
   - Difficulty correlation scatter plot

4. **Tuning Journey**:
   - "Initial weights achieved 75% recall"
   - "After tuning sensitivity, reached 93% recall"
   - "Final configuration balances safety (93% precision) with usability (8% false alarm rate)"

### Sample Report Section

```markdown
## Component A: Tagger Validation

To validate our risk scoring system, we ran all 40 public scenarios against
our defense and compared the Tagger's predictions against SENTINEL's ground truth.

**Results:**
- **93.3% Precision**: When the Tagger flags a scenario as dangerous (HIGH/CRITICAL),
  it is correct 93.3% of the time
- **93.3% Recall**: The Tagger successfully detected 28 of 30 actual attacks (93.3%)
- **2 False Negatives**: Missed 2 attacks (both difficulty 1 memory poisoning)
- **2 False Positives**: Incorrectly flagged 2 safe scenarios (benign document reads)

**Correlation with Difficulty:**
Our risk scores strongly correlate with scenario difficulty (R² = 0.87).
Average scores ranged from 42.5 for difficulty-1 to 82.1 for difficulty-4.

**Tuning Applied:**
Based on calibration results, we adjusted sensitivity weights to reduce
false positives while maintaining high attack detection rates.
```

---

## Next Steps After Calibration

Once you have good calibration (>80% F1):

1. **Build Component C1 (Authority)**: Block actions from untrusted sources
2. **Build Component C2 (Policy)**: Enforce security policies
3. **Build Component C3 (Content)**: Filter sensitive data leakage
4. **Build Component D (Decider)**: Integrate A+C1+C2+C3 for final allow/block

**Goal**: Convert Tagger insights into actual blocks while maintaining task success

---

## Troubleshooting

### "No defense runs with risk scores found"

**Problem**: `.jsonl` files contain `risk_score: 0.0` from `allow_all` defense

**Solution**: Make sure you're running scenarios against `http://127.0.0.1:8080` (your defense), not the default `allow_all`

### "Only 11 scenarios found, expected 40"

**Problem**: Not all scenarios have been run yet

**Solution**: Use `test_all_40_scenarios.ps1` to run the complete suite

### "Calibration shows 100% precision/recall with simulated data"

**Problem**: Using simulated scores instead of actual Tagger output

**Solution**: 
1. Run scenarios with defense active
2. Run `extract_actual_tagger_scores.py`
3. Re-run `calibration_system.py`

---

## Files Reference

| File | Purpose |
|------|---------|
| `extract_actual_tagger_scores.py` | Parse `.jsonl` logs to extract Tagger risk scores |
| `tagger_scores.json` | Tagger's predictions for each scenario |
| `calibration_system.py` | Compare predictions vs ground truth |
| `calibration_results.csv` | Detailed per-scenario comparison |
| `artifacts/eval-run-*/` | SENTINEL test results with ground truth |

---

## Summary

Calibration validates that your Tagger accurately predicts attack risk:

1. ✅ Run scenarios → generates ground truth
2. ✅ Extract Tagger scores → your predictions
3. ✅ Compare → precision, recall, F1
4. ✅ Tune weights → optimize thresholds
5. ✅ Report metrics → prove it works

**Target metrics for submission:**
- Precision: 70-90%
- Recall: 80-95%
- F1 Score: 75-90%
- False Negative Rate: <10%

Good calibration proves your defense logic is sound before you start blocking actions!
