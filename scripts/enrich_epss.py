#!/usr/bin/env python3
"""
🎯 EPSS Score Enrichment Module
Fetches EPSS (Exploit Prediction Scoring System) data from FIRST.org API
"""

import requests
import json
from typing import Tuple

try:
    from scripts.schema_utils import extract_cves
except ImportError:
    from schema_utils import extract_cves

EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 5  # seconds


def get_epss_score(cve_id: str) -> Tuple[float, float]:
    """
    Query the FIRST.org EPSS API for a given CVE ID.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        
    Returns:
        Tuple of (epss_score, percentile) as floats.
        Returns (0.0, 0.0) on any error.
        
    Example:
        >>> score, percentile = get_epss_score("CVE-2021-44228")
        >>> print(f"EPSS: {score:.4f}, Percentile: {percentile:.2f}")
    """
    if not cve_id or not str(cve_id).upper().startswith("CVE-"):
        return (0.0, 0.0)
    
    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id.upper()},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        
        data = response.json()
        
        # API returns {"status": "OK", "data": [{"cve": "...", "epss": "0.xxxxx", "percentile": "0.xxxxx"}]}
        if data.get("status") == "OK" and data.get("data"):
            epss_data = data["data"][0]
            epss_score = float(epss_data.get("epss", 0.0))
            percentile = float(epss_data.get("percentile", 0.0))
            return (epss_score, percentile)
        
        return (0.0, 0.0)
        
    except requests.exceptions.RequestException:
        # Network error, timeout, etc.
        return (0.0, 0.0)
    except (KeyError, IndexError, ValueError, TypeError):
        # JSON parsing error or unexpected format
        return (0.0, 0.0)


def get_epss_scores_batch(cve_ids: list, batch_size: int = 100) -> dict:
    """
    Batch query the FIRST.org EPSS API for multiple CVEs at once.
    
    Args:
        cve_ids: List of CVE identifiers (e.g., ["CVE-2021-44228", "CVE-2017-5638"])
        batch_size: Number of CVEs per API request (max ~100 recommended)
        
    Returns:
        Dict mapping CVE ID -> (epss_score, percentile).
        Missing/errored CVEs are not included in the dict.
    """
    results = {}
    
    if not cve_ids:
        return results
    
    # Dedupe and filter valid CVEs
    valid_cves = list(set(
        cve.strip().upper() for cve in cve_ids 
        if cve and str(cve).strip().upper().startswith("CVE-")
    ))
    
    # Process in batches
    for i in range(0, len(valid_cves), batch_size):
        batch = valid_cves[i:i + batch_size]
        batch_str = ",".join(batch)
        
        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": batch_str},
                timeout=30  # Longer timeout for batch
            )
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "OK" and data.get("data"):
                for entry in data["data"]:
                    cve = entry.get("cve", "").upper()
                    score = float(entry.get("epss", 0.0))
                    percentile = float(entry.get("percentile", 0.0))
                    results[cve] = (score, percentile)
                    
        except requests.exceptions.RequestException:
            # On network error, fall back to individual queries for this batch
            for cve in batch:
                score, pct = get_epss_score(cve)
                if score > 0:
                    results[cve] = (score, pct)
        except (KeyError, IndexError, ValueError, TypeError):
            pass
    
    return results


def summarize_epss_for_cves(cves: list, epss_results: dict) -> dict:
    """Return max EPSS metadata for one finding's CVE list."""
    cve_items = []
    for cve in cves:
        score, percentile = epss_results.get(cve.upper(), (0.0, 0.0))
        cve_items.append({
            "cve": cve.upper(),
            "epss": float(score),
            "percentile": float(percentile),
        })

    if not cve_items:
        return {
            "epss_score": 0.0,
            "epss_percentile": 0.0,
            "epss_source_cve": "",
            "epss_all_json": "[]",
            "epss_lookup_status": "NO_CVE",
        }

    best = max(cve_items, key=lambda item: item["epss"])
    found_any = any(item["cve"] in epss_results for item in cve_items)
    return {
        "epss_score": best["epss"],
        "epss_percentile": best["percentile"],
        "epss_source_cve": best["cve"] if best["epss"] > 0 else "",
        "epss_all_json": json.dumps(cve_items, ensure_ascii=False),
        "epss_lookup_status": "FOUND" if found_any else "NO_DATA_OR_LOOKUP_FAILED",
    }


def enrich_dataframe_with_epss(df, cve_column: str = "cve"):
    """
    Bulk enrich a DataFrame with EPSS scores.
    
    Args:
        df: pandas DataFrame with CVE IDs
        cve_column: Name of the column containing CVE IDs
        
    Returns:
        DataFrame with added 'epss_score' and 'epss_percentile' columns
    """
    import pandas as pd
    
    row_cves = []
    all_cves = []

    for _, row in df.iterrows():
        cves = extract_cves(row.get(cve_column, ""), row.get("cve_list", ""))
        row_cves.append(cves)
        all_cves.extend(cves)

    epss_results = get_epss_scores_batch(all_cves)

    summaries = [summarize_epss_for_cves(cves, epss_results) for cves in row_cves]
    df["epss_score"] = [item["epss_score"] for item in summaries]
    df["epss_percentile"] = [item["epss_percentile"] for item in summaries]
    df["epss_source_cve"] = [item["epss_source_cve"] for item in summaries]
    df["epss_all_json"] = [item["epss_all_json"] for item in summaries]
    df["epss_lookup_status"] = [item["epss_lookup_status"] for item in summaries]
    
    return df


if __name__ == "__main__":
    # Quick test
    test_cves = ["CVE-2021-44228", "CVE-2017-5638", "CVE-9999-99999"]
    print("🧪 Testing EPSS API...")
    for cve in test_cves:
        score, pct = get_epss_score(cve)
        print(f"   {cve}: EPSS={score:.5f}, Percentile={pct:.2%}")
