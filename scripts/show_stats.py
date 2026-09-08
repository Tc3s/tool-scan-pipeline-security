#!/usr/bin/env python3
"""Quick stats viewer for enriched findings"""
import csv
import os
from collections import Counter

try:
    from scripts import runtime_context as rt
except ImportError:
    import runtime_context as rt

def show_stats(csv_file):
    findings = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        findings = list(csv.DictReader(f))
    
    print(f"📊 Total findings: {len(findings)}\n")
    
    # Priority breakdown
    priorities = Counter(f.get('priority', '') for f in findings)
    print("🎯 Priority breakdown:")
    for p in ['P1', 'P2', 'P3', 'P4']:
        print(f"   {p}: {priorities[p]}")
    
    # Top techniques
    techniques = Counter(f"{f['attack_technique_id']} - {f['attack_technique_name']}" 
                         for f in findings if f.get('attack_technique_id'))
    print(f"\n🔍 Top 5 ATT&CK Techniques:")
    for tech, count in techniques.most_common(5):
        print(f"   {count:2d}x {tech}")
    
    # Top tactics
    tactics = Counter(f.get('attack_tactic', '') for f in findings)
    print(f"\n⚔️  Tactic distribution:")
    for tactic, count in tactics.most_common():
        print(f"   {count:2d}x {tactic}")
    
    # Show P1/P2 findings
    print(f"\n🚨 High Priority Findings (P1/P2):")
    high_pri = [f for f in findings if f.get('priority') in ['P1', 'P2']]
    if not high_pri:
        print("   (No P1/P2 findings - consider adjusting thresholds for demo)")
    else:
        for f in sorted(high_pri, key=lambda x: (x.get('priority', ''), -float(x.get('risk_score') or 0))):
            score = float(f.get('risk_score') or 0)
            print(f"   [{f.get('priority', '')}] {score:4.1f} | {f.get('finding_name', '')[:60]}")
            reason = f.get('risk_reason', f.get('reason', ''))
            print(f"        → {reason[:80]}")

if __name__ == '__main__':
    import sys
    from pathlib import Path

    if len(sys.argv) > 1 and sys.argv[1]:
        csv_target = Path(sys.argv[1])
    else:
        # Check current run output dir first
        candidates = [
            rt.output_dir() / 'vuln_validation_queue.csv',
            rt.output_dir() / 'vuln_attack_enriched.csv',
        ]
        # Check latest runs directory if current run is empty
        runs_dir = rt.project_root() / 'runs'
        if runs_dir.exists():
            recent_runs = sorted(runs_dir.glob('run_*'), key=lambda p: p.stat().st_mtime, reverse=True)
            for r in recent_runs:
                candidates.extend([
                    r / 'output' / 'vuln_validation_queue.csv',
                    r / 'output' / 'vuln_attack_enriched.csv',
                ])
        csv_target = next((c for c in candidates if c.exists()), None)

    if csv_target and csv_target.exists():
        print(f"📖 Reading: {csv_target}")
        show_stats(csv_target)
    else:
        print("❌ Error: No enriched or validation queue CSV found. Please specify a file: python3 scripts/show_stats.py <path_to_csv>")
        sys.exit(1)

