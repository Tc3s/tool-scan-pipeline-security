#!/usr/bin/env python3
"""Quick stats viewer for enriched findings"""
import csv
from collections import Counter

def show_stats(csv_file):
    findings = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        findings = list(csv.DictReader(f))
    
    print(f"📊 Total findings: {len(findings)}\n")
    
    # Priority breakdown
    priorities = Counter(f['priority'] for f in findings)
    print("🎯 Priority breakdown:")
    for p in ['P1', 'P2', 'P3', 'P4']:
        print(f"   {p}: {priorities[p]}")
    
    # Top techniques
    techniques = Counter(f"{f['attack_technique_id']} - {f['attack_technique_name']}" 
                         for f in findings if f['attack_technique_id'])
    print(f"\n🔍 Top 5 ATT&CK Techniques:")
    for tech, count in techniques.most_common(5):
        print(f"   {count:2d}x {tech}")
    
    # Top tactics
    tactics = Counter(f['attack_tactic'] for f in findings)
    print(f"\n⚔️  Tactic distribution:")
    for tactic, count in tactics.most_common():
        print(f"   {count:2d}x {tactic}")
    
    # Show P1/P2 findings
    print(f"\n🚨 High Priority Findings (P1/P2):")
    high_pri = [f for f in findings if f['priority'] in ['P1', 'P2']]
    if not high_pri:
        print("   (No P1/P2 findings - consider adjusting thresholds for demo)")
    else:
        for f in sorted(high_pri, key=lambda x: (x['priority'], -float(x['risk_score']))):
            score = float(f['risk_score'])
            print(f"   [{f['priority']}] {score:4.1f} | {f['finding_name'][:60]}")
            print(f"        → {f['attack_technique_id']} {f['attack_technique_name']}")
            print(f"        → {f['reason'][:80]}")

if __name__ == '__main__':
    show_stats('data/output/vuln_attack_enriched.csv')
