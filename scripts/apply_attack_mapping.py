#!/usr/bin/env python3

"""
✅ OPTIMIZED: Apply Rule-Based ATT&CK Mapping

Input:  data/normalized/zap_findings.csv (from parse_zap.py)
Output: data/output/vuln_attack_mapped.csv

Improvements from v8:
- ✅ Robust error handling
- ✅ Progress indicator
- ✅ Better CWE/CVE matching
- ✅ Standardized output columns
- ✅ Comprehensive logging
- ✅ Summary statistics
"""

import csv
import yaml
import re
import sys
from pathlib import Path
from datetime import datetime

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
    """Match CVE with pattern (prefix match or regex)"""
    if not cve or not pattern:
        return False
    try:
        if pattern.startswith('/') and pattern.endswith('/'):
            # Regex pattern
            regex = pattern[1:-1]
            return bool(re.match(regex, cve, re.IGNORECASE))
        else:
            # Simple prefix match
            return cve.upper().startswith(pattern.upper())
    except re.error:
        return False

# ============== MAPPING ENGINE ==============
def apply_mapping(finding, rules):
    """Apply first matching rule to finding - returns standardized dict"""
    finding_name = finding.get('finding_name', '')
    cwe = finding.get('cwe', '')
    cve = finding.get('cve', '')
    
    for rule in rules:
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
            # Convert confidence to float
            try:
                confidence = float(rule.get('confidence', 0.5))
            except (ValueError, TypeError):
                confidence = 0.5
            
            return {
                'attack_tactic': rule.get('tactic', 'Unknown').strip(),
                'attack_technique_id': rule.get('technique_id', '').strip(),
                'attack_technique_name': rule.get('technique_name', '').strip(),
                'attack_confidence': confidence,
                'mapping_method': 'rule',
                'reason': rule.get('reason', 'Rule-based mapping').strip(),
                'needs_review': confidence < 0.7  # Mark low-confidence for review
            }
    
    # No match → return unknown with empty fields
    return {
        'attack_tactic': 'Unknown',
        'attack_technique_id': '',
        'attack_technique_name': '',
        'attack_confidence': 0.0,
        'mapping_method': 'rule_no_match',
        'reason': 'No matching rule found',
        'needs_review': True  # All unmapped need review
    }

# ============== CSV PROCESSING ==============
def load_findings(input_csv):
    """Load findings from CSV"""
    try:
        findings = []
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
        return findings
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
                      'attack_confidence', 'mapping_method', 'reason', 'needs_review']
        
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
        if mapping['attack_technique_id']:
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
    print(f"  ✅ Mapped:     {stats['mapped']:3d}/{stats['total']} ({mapped_pct:5.1f}%)")
    print(f"  ⭕ Unmapped:   {stats['unmapped']:3d}/{stats['total']} ({100-mapped_pct:5.1f}%) → AI enrichment needed")
    
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
    print(f"\n✨ Next: Apply AI mapping to {stats['unmapped']} unmapped findings")
    print(f"   Run: python3 scripts/ai_attack_mapping.py")
    print(f"   Or:  python3 scripts/ai_attack_mapping_mock.py (no API key needed)\n")
    
    return mapped_findings

# ============== ENTRY POINT ==============
if __name__ == '__main__':
    input_file = 'data/output/vuln_raw.csv'
    rules_file = 'mapping/attack_mapping_rules.yml'
    output_file = 'data/output/vuln_attack_mapped.csv'
    
    # Validate input files exist
    if not Path(input_file).exists():
        Logger.error(f"Input file not found: {input_file}")
        sys.exit(1)
    
    if not Path(rules_file).exists():
        Logger.error(f"Rules file not found: {rules_file}")
        sys.exit(1)
    
    process_findings(input_file, rules_file, output_file)
