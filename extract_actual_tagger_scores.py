#!/usr/bin/env python3
"""
Extract Actual Tagger Scores from Defense Runs
===============================================

This script extracts the real risk scores calculated by Component A (Tagger)
from SENTINEL test runs where your defense was active.

It parses the .jsonl log files to get the actual risk_score from each
defense decision.
"""

import json
import glob
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class StepScore:
    """Risk score for a single step"""
    step_id: int
    risk_score: float
    decision: str
    action_type: str
    tool: str = None
    legitimate: bool = True


@dataclass
class ScenarioScores:
    """All risk scores for a scenario"""
    scenario_id: str
    steps: List[StepScore]
    
    @property
    def avg_risk(self) -> float:
        if not self.steps:
            return 0.0
        return sum(s.risk_score for s in self.steps) / len(self.steps)
    
    @property
    def max_risk(self) -> float:
        if not self.steps:
            return 0.0
        return max(s.risk_score for s in self.steps)
    
    @property
    def min_risk(self) -> float:
        if not self.steps:
            return 0.0
        return min(s.risk_score for s in self.steps)
    
    def count_by_classification(self):
        """Count steps by risk classification"""
        critical = sum(1 for s in self.steps if s.risk_score >= 76)
        high = sum(1 for s in self.steps if 56 <= s.risk_score < 76)
        moderate = sum(1 for s in self.steps if 36 <= s.risk_score < 56)
        low = sum(1 for s in self.steps if 16 <= s.risk_score < 36)
        safe = sum(1 for s in self.steps if s.risk_score < 16)
        
        return {
            'critical': critical,
            'high': high,
            'moderate': moderate,
            'low': low,
            'safe': safe,
            'total': len(self.steps)
        }


def extract_scores_from_jsonl(jsonl_path: str) -> ScenarioScores:
    """
    Extract risk scores from a SENTINEL .jsonl log file
    
    Each line in the .jsonl file is a step with defense decision data
    """
    steps = []
    scenario_id = Path(jsonl_path).stem.split('-')[0]  # Extract from filename
    
    with open(jsonl_path, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                # Extract defense decision
                defense = data.get('defense', {})
                if not defense:
                    continue
                
                step_score = StepScore(
                    step_id=data.get('step_id', 0),
                    risk_score=defense.get('risk_score', 0.0),
                    decision=defense.get('decision', 'unknown'),
                    action_type=data.get('action_type', 'unknown'),
                    tool=data.get('tool'),
                    legitimate=defense.get('legitimate', True)
                )
                
                steps.append(step_score)
                
            except json.JSONDecodeError as e:
                print(f"⚠️  Error parsing line in {jsonl_path}: {e}")
                continue
    
    return ScenarioScores(scenario_id=scenario_id, steps=steps)


def scan_artifacts(artifacts_dir: str = "artifacts") -> Dict[str, ScenarioScores]:
    """Scan all artifacts for defense run data"""
    print(f"🔍 Scanning {artifacts_dir} for defense runs...")
    
    jsonl_files = glob.glob(
        str(Path(artifacts_dir) / "**" / "*.jsonl"),
        recursive=True
    )
    
    scores_by_scenario = {}
    
    for jsonl_file in jsonl_files:
        try:
            scores = extract_scores_from_jsonl(jsonl_file)
            
            if not scores.steps:
                print(f"⚠️  No defense data in {Path(jsonl_file).name}")
                continue
            
            # Check if this has actual risk scores (not 0.0 from allow_all)
            has_real_scores = any(s.risk_score > 0 for s in scores.steps)
            
            if not has_real_scores:
                print(f"⏭️  Skipping {scores.scenario_id} (allow_all defense, no risk scores)")
                continue
            
            scores_by_scenario[scores.scenario_id] = scores
            print(f"✅ {scores.scenario_id:40} | Steps: {len(scores.steps):2d} | "
                  f"Avg: {scores.avg_risk:5.1f} | Max: {scores.max_risk:5.1f}")
            
        except Exception as e:
            print(f"❌ Error processing {jsonl_file}: {e}")
    
    return scores_by_scenario


def export_tagger_scores_json(scores: Dict[str, ScenarioScores], output_file: str):
    """Export Tagger scores to JSON for calibration analysis"""
    data = {}
    
    for scenario_id, scores_obj in scores.items():
        counts = scores_obj.count_by_classification()
        
        data[scenario_id] = {
            'scenario_id': scenario_id,
            'avg_risk_score': scores_obj.avg_risk,
            'max_risk_score': scores_obj.max_risk,
            'min_risk_score': scores_obj.min_risk,
            'critical_steps': counts['critical'],
            'high_steps': counts['high'],
            'moderate_steps': counts['moderate'],
            'low_steps': counts['low'],
            'safe_steps': counts['safe'],
            'total_steps': counts['total'],
            'steps': [
                {
                    'step_id': s.step_id,
                    'risk_score': s.risk_score,
                    'decision': s.decision,
                    'action_type': s.action_type,
                    'tool': s.tool,
                    'legitimate': s.legitimate
                }
                for s in scores_obj.steps
            ]
        }
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n📄 Exported Tagger scores to {output_file}")


def main():
    """Extract Tagger scores from defense runs"""
    print("🚀 Extracting Actual Tagger Scores from Defense Runs\n")
    
    scores = scan_artifacts()
    
    if not scores:
        print("\n❌ No defense runs with risk scores found!")
        print("\nTo get actual Tagger scores:")
        print("1. Start your defense server:")
        print("   python -m uvicorn app.main:app --host 127.0.0.1 --port 8080")
        print("\n2. Run scenarios against your defense:")
        print("   uv run sentinel run --scenario scenarios/public/enterprise/enterprise_memory_poison.yaml --defense-url http://127.0.0.1:8080")
        print("\n3. Re-run this script to extract the scores")
        return
    
    print(f"\n✅ Found {len(scores)} scenarios with Tagger risk scores")
    
    # Export to JSON
    export_tagger_scores_json(scores, "tagger_scores.json")
    
    # Print summary
    print("\n📊 TAGGER SCORE SUMMARY")
    print("-" * 80)
    
    all_scores = [s.avg_risk for s in scores.values()]
    print(f"Total Scenarios:        {len(scores)}")
    print(f"Average Risk Score:     {sum(all_scores) / len(all_scores):.1f}")
    print(f"Highest Risk Scenario:  {max(all_scores):.1f}")
    print(f"Lowest Risk Scenario:   {min(all_scores):.1f}")
    
    # By classification
    critical_count = sum(1 for s in scores.values() if s.avg_risk >= 76)
    high_count = sum(1 for s in scores.values() if 56 <= s.avg_risk < 76)
    moderate_count = sum(1 for s in scores.values() if 36 <= s.avg_risk < 56)
    low_count = sum(1 for s in scores.values() if 16 <= s.avg_risk < 36)
    safe_count = sum(1 for s in scores.values() if s.avg_risk < 16)
    
    print(f"\nScenarios by Risk Classification:")
    print(f"  CRITICAL (76-100):    {critical_count:2d}")
    print(f"  HIGH (56-75):         {high_count:2d}")
    print(f"  MODERATE (36-55):     {moderate_count:2d}")
    print(f"  LOW (16-35):          {low_count:2d}")
    print(f"  SAFE (0-15):          {safe_count:2d}")
    
    print("\n✅ Use tagger_scores.json with calibration_system.py for full analysis")


if __name__ == "__main__":
    main()
