#!/usr/bin/env python3

"""
✅ OPTIMIZED: Apply Rule-Based ATT&CK Mapping

Input:  data/normalized/zap_findings.csv (from parse_zap.py)
Output: data/output/vuln_attack_mapped.csv

V1 baseline:
- ✅ Robust error handling
- ✅ Progress indicator
- ✅ Better CWE/CVE matching
- ✅ Standardized output columns
- ✅ Comprehensive logging
- ✅ Summary statistics
"""

import csv
import json
import yaml
import re
import sys
import os
from pathlib import Path
from datetime import datetime
import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import extract_cves, normalize_dataframe_schema
except ImportError:
    import runtime_context as rt
    from schema_utils import extract_cves, normalize_dataframe_schema

# ============== LOGGING ==============
class Logger:
    @staticmethod
    def info(msg):
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] ℹ️  {msg}")
    
    @staticmethod
    def success(msg):
        print(f"✅ {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"⚠️  {msg}")
    
    @staticmethod
    def error(msg):
        print(f"❌ {msg}")

# ============== RULE LOADER ==============
def load_rules(rules_file):
    """Load mapping rules from YAML with error handling"""
    try:
        with open(rules_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            rules = data.get('rules', [])
            if not rules:
                Logger.warning(f"No rules found in {rules_file}")
                return []
            Logger.success(f"Loaded {len(rules)} mapping rules")
            return rules
    except FileNotFoundError:
        Logger.error(f"Rules file not found: {rules_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        Logger.error(f"Invalid YAML in {rules_file}: {e}")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Failed to load rules: {e}")
        sys.exit(1)

# ============== MATCHING LOGIC ==============
def match_finding_name(finding_name, pattern):
    """Match finding name (case-insensitive, regex support)"""
    try:
        return bool(re.search(pattern, finding_name, re.IGNORECASE))
    except re.error:
        return False

def match_cwe(cwe, pattern):
    """Match CWE code exactly"""
    if not cwe or not pattern:
        return False
    return pattern.upper() in cwe.upper()

def match_cve(cve, pattern):
    """Match any CVE in a finding with pattern (prefix match or regex)."""
    cves = extract_cves(cve)
    if not cves or not pattern:
        return False
    try:
        if pattern.startswith('/') and pattern.endswith('/'):
            # Regex pattern
            regex = pattern[1:-1]
            return any(re.match(regex, cve_id, re.IGNORECASE) for cve_id in cves)
        else:
            # Simple prefix match
            return any(cve_id.upper().startswith(pattern.upper()) for cve_id in cves)
    except re.error:
        return False

# ============== MAPPING ENGINE ==============
def _is_catch_all(rule):
    pattern = str(rule.get('pattern', '')).strip()
    return pattern in {'.*', '^.*$', '.+'} and float(rule.get('confidence', 0) or 0) < 0.7


def apply_mapping(finding, rules):
    """Apply all matching rules and return primary + JSON technique mappings."""
    finding_name = finding.get('finding_name', '')
    cwe = finding.get('cwe', '')
    cve = finding.get('cve', '')
    matches = []

    for rule in rules:
        if _is_catch_all(rule):
            continue

        match_type = rule.get('match_type', '').lower()
        pattern = rule.get('pattern', '')
        matched = False
        
        if match_type == 'finding_name' and match_finding_name(finding_name, pattern):
            matched = True
        elif match_type == 'cwe' and match_cwe(cwe, pattern):
            matched = True
        elif match_type == 'cve' and match_cve(cve, pattern):
            matched = True
        
        if matched:
            try:
                confidence = float(rule.get('confidence', 0.5))
            except (ValueError, TypeError):
                confidence = 0.5
            matches.append({
                'tactic': rule.get('tactic', 'Unknown').strip(),
                'technique_id': rule.get('technique_id', '').strip(),
                'technique_name': rule.get('technique_name', '').strip(),
                'confidence': confidence,
                'reason': rule.get('reason', 'Rule-based mapping').strip(),
                'match_type': match_type,
                'pattern': pattern,
            })

    deduped = []
    seen = set()
    for item in sorted(matches, key=lambda m: m['confidence'], reverse=True):
        key = item['technique_id'] or item['technique_name']
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    if deduped:
        primary = deduped[0]
        max_confidence = primary['confidence']
        return {
            'attack_tactic': primary['tactic'],
            'attack_technique_id': primary['technique_id'],
            'attack_technique_name': primary['technique_name'],
            'attack_confidence': max_confidence,
            'attack_tactics_json': json.dumps(sorted({item['tactic'] for item in deduped}), ensure_ascii=False),
            'attack_techniques_json': json.dumps(deduped, ensure_ascii=False),
            'mapping_method': 'rule_multi' if len(deduped) > 1 else 'rule',
            'mapping_type': 'heuristic_rule',
            'reason': primary['reason'],
            'needs_review': max_confidence < 0.7
        }
    
    # No match → return unknown with empty fields
    return {
        'attack_tactic': 'Unknown',
        'attack_technique_id': '',
        'attack_technique_name': '',
        'attack_confidence': 0.0,
        'attack_tactics_json': '[]',
        'attack_techniques_json': '[]',
        'mapping_method': 'rule_no_match',
        'mapping_type': 'heuristic_rule',
        'reason': 'No matching rule found',
        'needs_review': True  # All unmapped need review
    }

# ============== CSV PROCESSING ==============
def load_findings(input_csv):
    """Load findings from CSV"""
    try:
        with open(input_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                Logger.error(f"Empty CSV file: {input_csv}")
                return []
            findings = list(reader)
        
        if not findings:
            Logger.warning(f"No findings in {input_csv}")
        else:
            Logger.success(f"Loaded {len(findings)} findings from {input_csv}")
        return normalize_dataframe_schema(pd.read_csv(input_csv)).to_dict('records')
    except FileNotFoundError:
        Logger.error(f"Input file not found: {input_csv}")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Failed to read {input_csv}: {e}")
        sys.exit(1)

def save_findings(mapped_findings, output_csv):
    """Save mapped findings to CSV with standardized columns"""
    try:
        output_path = Path(output_csv)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not mapped_findings:
            Logger.error("No findings to save")
            return False
        
        # Get all fieldnames from first finding + add new fields if needed
        fieldnames = list(mapped_findings[0].keys())
        new_fields = ['attack_tactic', 'attack_technique_id', 'attack_technique_name',
                      'attack_confidence', 'attack_tactics_json', 'attack_techniques_json',
                      'mapping_method', 'mapping_type', 'reason', 'needs_review']
        
        for field in new_fields:
            if field not in fieldnames:
                fieldnames.append(field)
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in mapped_findings:
                # Ensure all fields exist
                for field in fieldnames:
                    if field not in finding:
                        finding[field] = ''
                writer.writerow(finding)
        
        Logger.success(f"Saved {len(mapped_findings)} findings to {output_path}")
        return True
    except Exception as e:
        Logger.error(f"Failed to save {output_csv}: {e}")
        return False

# ============== MAIN PROCESSING ==============
def process_findings(input_csv, rules_file, output_csv):
    """Apply rule-based mapping to all findings"""
    
    print("\n" + "="*70)
    print("🎯 RULE-BASED ATT&CK MAPPING")
    print("="*70 + "\n")
    
    # Load rules
    rules = load_rules(rules_file)
    if not rules:
        Logger.error("No rules loaded. Cannot continue.")
        sys.exit(1)
    
    # Load findings
    findings = load_findings(input_csv)
    if not findings:
        Logger.error("No findings loaded. Cannot continue.")
        sys.exit(1)
    
    # Apply mapping with progress
    print(f"\n📊 Processing {len(findings)} findings...")
    mapped_findings = []
    stats = {
        'total': len(findings),
        'mapped': 0,
        'unmapped': 0,
        'by_tactic': {},
        'by_confidence': {'high': 0, 'medium': 0, 'low': 0, 'zero': 0}
    }
    
    for i, finding in enumerate(findings):
        # Progress indicator
        if (i + 1) % max(1, len(findings) // 10) == 0 or i == 0:
            progress = (i + 1) / len(findings) * 100
            print(f"  [{progress:.0f}%] Processing finding {i+1}/{len(findings)}...", end='\r')
        
        mapping = apply_mapping(finding, rules)
        enriched = {**finding, **mapping}
        mapped_findings.append(enriched)
        
        # Update stats
        if mapping['attack_technique_id'] and mapping['attack_confidence'] >= 0.7:
            stats['mapped'] += 1
        else:
            stats['unmapped'] += 1
        
        # Tactic stats
        tactic = mapping['attack_tactic']
        stats['by_tactic'][tactic] = stats['by_tactic'].get(tactic, 0) + 1
        
        # Confidence stats
        confidence = mapping['attack_confidence']
        if confidence >= 0.9:
            stats['by_confidence']['high'] += 1
        elif confidence >= 0.7:
            stats['by_confidence']['medium'] += 1
        elif confidence > 0:
            stats['by_confidence']['low'] += 1
        else:
            stats['by_confidence']['zero'] += 1
    
    print(f"\n  [100%] Processing complete!                  \n")
    
    # Save findings
    if not save_findings(mapped_findings, output_csv):
        sys.exit(1)
    
    # Show statistics
    print("\n" + "="*70)
    print("📈 MAPPING STATISTICS")
    print("="*70)
    
    mapped_pct = (stats['mapped'] / stats['total'] * 100) if stats['total'] > 0 else 0
    print(f"\nCoverage:")
    print(f"  ✅ Trusted mapped (confidence ≥0.7): {stats['mapped']:3d}/{stats['total']} ({mapped_pct:5.1f}%)")
    print(f"  ⭕ Unknown/needs review:             {stats['unmapped']:3d}/{stats['total']} ({100-mapped_pct:5.1f}%)")
    
    print(f"\nConfidence Levels:")
    print(f"  🟢 High (≥0.9):  {stats['by_confidence']['high']:3d}")
    print(f"  🟡 Medium (0.7-0.9): {stats['by_confidence']['medium']:3d}")
    print(f"  🔴 Low (0-0.7):  {stats['by_confidence']['low']:3d}")
    print(f"  ⚫ None (0):     {stats['by_confidence']['zero']:3d}")
    
    print(f"\nTactics Distribution:")
    sorted_tactics = sorted(stats['by_tactic'].items(), key=lambda x: x[1], reverse=True)
    for tactic, count in sorted_tactics[:10]:  # Top 10 tactics
        pct = (count / stats['total'] * 100)
        print(f"  • {tactic:25s}: {count:3d} ({pct:5.1f}%)")
    
    if len(sorted_tactics) > 10:
        others_count = sum(count for _, count in sorted_tactics[10:])
        print(f"  • {'Other':25s}: {others_count:3d}")
    
    print("\n" + "="*70)
    print(f"\n✨ Next: Calculate risk priority")
    print(f"   Run: python3 scripts/calculate_risk_priority.py")
    if stats['unmapped']:
        print(f"   Note: {stats['unmapped']} findings still need manual ATT&CK mapping review.\n")
    
    return mapped_findings

# ============== ENTRY POINT ==============
if __name__ == '__main__':
    # Tìm thư mục gốc của project (script nằm trong scripts/)
    PROJECT_ROOT = rt.project_root()
    DATA_DIR = rt.run_dir()
    MAPPING_DIR = PROJECT_ROOT / "mapping"
    
    input_file = rt.output_dir() / 'vuln_raw.csv'
    rules_file = MAPPING_DIR / 'attack_mapping_rules.yml'
    output_file = rt.output_dir() / 'vuln_attack_mapped.csv'
    
    # Validate input files exist
    if not Path(input_file).exists():
        Logger.error(f"Input file not found: {input_file}")
        sys.exit(1)
    
    if not Path(rules_file).exists():
        Logger.error(f"Rules file not found: {rules_file}")
        sys.exit(1)
    
    process_findings(input_file, rules_file, output_file)
