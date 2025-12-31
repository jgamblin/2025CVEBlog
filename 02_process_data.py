#!/usr/bin/env python3
"""
Process CVE Data for 2025 CVE Review
Parses NVD JSON and CVE V5 List to create analysis-ready dataframes
"""

import os
import json
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

DATA_DIR = Path("data")
OUTPUT_DIR = Path("processed")
OUTPUT_DIR.mkdir(exist_ok=True)

def load_nvd_json():
    """Load and parse the NVD JSON file"""
    nvd_file = DATA_DIR / "nvd.json"
    
    print("Loading NVD JSON (this may take a while for 1GB+ file)...")
    
    with open(nvd_file, 'r') as f:
        data = json.load(f)
    
    # Handle different formats - could be array or object with CVE_Items/vulnerabilities
    if isinstance(data, list):
        print(f"Loaded NVD data with {len(data)} entries (array format)")
        return {'vulnerabilities': data}
    else:
        print(f"Loaded NVD data with {len(data.get('CVE_Items', data.get('vulnerabilities', [])))} entries")
        return data

def parse_nvd_data(nvd_data):
    """Parse NVD data into a DataFrame"""
    records = []
    
    # Handle different NVD JSON formats
    items = nvd_data.get('CVE_Items', nvd_data.get('vulnerabilities', []))
    
    print(f"Parsing {len(items):,} NVD entries...")
    
    for item in tqdm(items):
        try:
            # Handle both old and new NVD API formats
            if 'cve' in item:
                cve_data = item['cve']
                
                # New API format (2.0)
                if 'id' in cve_data:
                    cve_id = cve_data['id']
                    published = cve_data.get('published', '')
                    modified = cve_data.get('lastModified', '')
                    
                    # Get description
                    descriptions = cve_data.get('descriptions', [])
                    description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
                    
                    # Get CVSS scores
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = None
                    cvss_v2 = None
                    cvss_v4 = None
                    severity = None
                    
                    # CVSS v4
                    if 'cvssMetricV40' in metrics:
                        cvss_v4_data = metrics['cvssMetricV40']
                        if cvss_v4_data:
                            cvss_v4 = cvss_v4_data[0].get('cvssData', {}).get('baseScore')
                            severity = cvss_v4_data[0].get('cvssData', {}).get('baseSeverity')
                    
                    # CVSS v3.1
                    if 'cvssMetricV31' in metrics:
                        cvss_v3_data = metrics['cvssMetricV31']
                        if cvss_v3_data:
                            cvss_v3 = cvss_v3_data[0].get('cvssData', {}).get('baseScore')
                            if not severity:
                                severity = cvss_v3_data[0].get('cvssData', {}).get('baseSeverity')
                    
                    # CVSS v3.0
                    if 'cvssMetricV30' in metrics and cvss_v3 is None:
                        cvss_v3_data = metrics['cvssMetricV30']
                        if cvss_v3_data:
                            cvss_v3 = cvss_v3_data[0].get('cvssData', {}).get('baseScore')
                            if not severity:
                                severity = cvss_v3_data[0].get('cvssData', {}).get('baseSeverity')
                    
                    # CVSS v2
                    if 'cvssMetricV2' in metrics:
                        cvss_v2_data = metrics['cvssMetricV2']
                        if cvss_v2_data:
                            cvss_v2 = cvss_v2_data[0].get('cvssData', {}).get('baseScore')
                            if not severity:
                                severity = cvss_v2_data[0].get('baseSeverity')
                    
                    # Get CWE
                    weaknesses = cve_data.get('weaknesses', [])
                    cwes = []
                    for weakness in weaknesses:
                        for desc in weakness.get('description', []):
                            if desc.get('value', '').startswith('CWE-'):
                                cwes.append(desc['value'])
                    cwe = cwes[0] if cwes else None
                    
                    # Get CPE
                    configurations = cve_data.get('configurations', [])
                    cpes = []
                    for config in configurations:
                        for node in config.get('nodes', []):
                            for cpe_match in node.get('cpeMatch', []):
                                cpes.append(cpe_match.get('criteria', ''))
                    
                    # Get references
                    references = cve_data.get('references', [])
                    ref_count = len(references)
                    
                    # Vuln status
                    vuln_status = cve_data.get('vulnStatus', '')
                    
                else:
                    # Old API format
                    cve_meta = cve_data.get('CVE_data_meta', {})
                    cve_id = cve_meta.get('ID', '')
                    published = item.get('publishedDate', '')
                    modified = item.get('lastModifiedDate', '')
                    
                    # Description
                    desc_data = cve_data.get('description', {}).get('description_data', [])
                    description = next((d['value'] for d in desc_data if d.get('lang') == 'en'), '')
                    
                    # CVSS
                    impact = item.get('impact', {})
                    cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
                    cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')
                    cvss_v4 = None
                    severity = impact.get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity')
                    if not severity:
                        severity = impact.get('baseMetricV2', {}).get('severity')
                    
                    # CWE
                    problemtype = cve_data.get('problemtype', {}).get('problemtype_data', [])
                    cwes = []
                    for pt in problemtype:
                        for desc in pt.get('description', []):
                            if desc.get('value', '').startswith('CWE-'):
                                cwes.append(desc['value'])
                    cwe = cwes[0] if cwes else None
                    
                    # CPE
                    configurations = item.get('configurations', {})
                    cpes = []
                    for node in configurations.get('nodes', []):
                        for cpe_match in node.get('cpe_match', []):
                            cpes.append(cpe_match.get('cpe23Uri', ''))
                    
                    ref_count = len(cve_data.get('references', {}).get('reference_data', []))
                    vuln_status = ''
            
            else:
                continue
            
            # Parse dates
            try:
                pub_date = pd.to_datetime(published)
            except:
                pub_date = None
            
            try:
                mod_date = pd.to_datetime(modified)
            except:
                mod_date = None
            
            # Extract year from CVE ID (for reference)
            try:
                cve_year = int(cve_id.split('-')[1])
            except:
                cve_year = None
            
            # Use published date year as the primary year for analysis
            if pub_date is not None:
                year = pub_date.year
            else:
                year = cve_year
            
            # Determine if CVE is rejected
            is_rejected = False
            if vuln_status:
                is_rejected = vuln_status.upper() in ['REJECTED', 'REJECT']
            if not is_rejected and description:
                # Check description for rejection indicators
                desc_lower = description.lower()
                is_rejected = ('** reject **' in desc_lower or 
                               '** disputed **' in desc_lower or
                               'this cve id has been rejected' in desc_lower)
            
            records.append({
                'cve_id': cve_id,
                'year': year,
                'cve_year': cve_year,  # Year from CVE ID for reference
                'published': pub_date,
                'modified': mod_date,
                'description': description[:500] if description else '',
                'cvss_v2': cvss_v2,
                'cvss_v3': cvss_v3,
                'cvss_v4': cvss_v4,
                'severity': severity,
                'cwe': cwe,
                'cpe_count': len(cpes),
                'has_cpe': len(cpes) > 0,
                'ref_count': ref_count,
                'vuln_status': vuln_status,
                'is_rejected': is_rejected
            })
            
        except Exception as e:
            continue
    
    df = pd.DataFrame(records)
    print(f"Created DataFrame with {len(df):,} CVEs")
    return df

def parse_cvelistv5():
    """Parse CVE List V5 repository"""
    cvelist_dir = DATA_DIR / "cvelistV5" / "cves"
    
    if not cvelist_dir.exists():
        # Try alternate path
        cvelist_dir = DATA_DIR / "cvelistV5"
    
    print(f"Parsing CVE List V5 from {cvelist_dir}...")
    
    records = []
    cve_files = list(cvelist_dir.rglob("CVE-*.json"))
    
    print(f"Found {len(cve_files):,} CVE files")
    
    for cve_file in tqdm(cve_files):
        try:
            with open(cve_file, 'r') as f:
                data = json.load(f)
            
            # Get CVE ID
            cve_id = data.get('cveMetadata', {}).get('cveId', cve_file.stem)
            
            # Get metadata
            metadata = data.get('cveMetadata', {})
            state = metadata.get('state', '')
            date_reserved = metadata.get('dateReserved', '')
            date_published = metadata.get('datePublished', '')
            date_updated = metadata.get('dateUpdated', '')
            assigner_org = metadata.get('assignerOrgId', '')
            assigner_short = metadata.get('assignerShortName', '')
            
            # Get container data
            containers = data.get('containers', {})
            cna = containers.get('cna', {})
            
            # Get affected products
            affected = cna.get('affected', [])
            vendors = []
            products = []
            for aff in affected:
                vendor = aff.get('vendor', '')
                product = aff.get('product', '')
                if vendor:
                    vendors.append(vendor)
                if product:
                    products.append(product)
            
            # Get problem types (CWE)
            problem_types = cna.get('problemTypes', [])
            cwes = []
            for pt in problem_types:
                for desc in pt.get('descriptions', []):
                    cwe_id = desc.get('cweId', '')
                    if cwe_id:
                        cwes.append(cwe_id)
            
            # Get CVSS metrics
            metrics = cna.get('metrics', [])
            cvss_v3 = None
            cvss_v4 = None
            severity = None
            
            for metric in metrics:
                if 'cvssV4_0' in metric:
                    cvss_v4 = metric['cvssV4_0'].get('baseScore')
                    severity = metric['cvssV4_0'].get('baseSeverity')
                if 'cvssV3_1' in metric:
                    cvss_v3 = metric['cvssV3_1'].get('baseScore')
                    if not severity:
                        severity = metric['cvssV3_1'].get('baseSeverity')
                if 'cvssV3_0' in metric and cvss_v3 is None:
                    cvss_v3 = metric['cvssV3_0'].get('baseScore')
                    if not severity:
                        severity = metric['cvssV3_0'].get('baseSeverity')
            
            # Get description
            descriptions = cna.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
            
            # Get references
            references = cna.get('references', [])
            
            # Extract year from CVE ID (for reference)
            try:
                cve_year = int(cve_id.split('-')[1])
            except:
                cve_year = None
            
            # Parse dates
            try:
                pub_date = pd.to_datetime(date_published) if date_published else None
            except:
                pub_date = None
            
            try:
                reserved_date = pd.to_datetime(date_reserved) if date_reserved else None
            except:
                reserved_date = None
            
            # Use published date year as the primary year for analysis
            if pub_date is not None:
                year = pub_date.year
            else:
                year = cve_year
            
            records.append({
                'cve_id': cve_id,
                'year': year,
                'cve_year': cve_year,  # Year from CVE ID for reference
                'state': state,
                'date_reserved': reserved_date,
                'date_published': pub_date,
                'assigner_org_id': assigner_org,
                'assigner_short_name': assigner_short,
                'vendor': vendors[0] if vendors else None,
                'product': products[0] if products else None,
                'vendor_count': len(set(vendors)),
                'product_count': len(set(products)),
                'cwe': cwes[0] if cwes else None,
                'cwe_count': len(cwes),
                'cvss_v3': cvss_v3,
                'cvss_v4': cvss_v4,
                'severity': severity,
                'description': description[:500] if description else '',
                'ref_count': len(references),
                'is_rejected': state == 'REJECTED',
                'is_published': state == 'PUBLISHED'
            })
            
        except Exception as e:
            continue
    
    df = pd.DataFrame(records)
    print(f"Created CVE V5 DataFrame with {len(df):,} CVEs")
    return df

def analyze_cnas(cvelist_df):
    """Analyze CNA (CVE Numbering Authority) statistics"""
    print("Analyzing CNA statistics...")
    
    cna_stats = cvelist_df.groupby('assigner_short_name').agg({
        'cve_id': 'count',
        'is_published': 'sum',
        'is_rejected': 'sum',
        'cvss_v3': lambda x: x.notna().sum(),
        'cwe': lambda x: x.notna().sum()
    }).rename(columns={
        'cve_id': 'total_cves',
        'is_published': 'published',
        'is_rejected': 'rejected',
        'cvss_v3': 'has_cvss',
        'cwe': 'has_cwe'
    })
    
    cna_stats = cna_stats.sort_values('total_cves', ascending=False)
    return cna_stats

def main():
    print("="*60)
    print("2025 CVE Data Processing")
    print("="*60)
    
    # Process NVD data
    print("\n[1/3] Processing NVD JSON...")
    try:
        nvd_data = load_nvd_json()
        nvd_df = parse_nvd_data(nvd_data)
        nvd_df.to_parquet(OUTPUT_DIR / "nvd_cves.parquet", index=False)
        nvd_df.to_csv(OUTPUT_DIR / "nvd_cves.csv", index=False)
        print(f"Saved NVD data to {OUTPUT_DIR}/nvd_cves.parquet")
        
        # Free memory
        del nvd_data
    except Exception as e:
        print(f"Error processing NVD data: {e}")
        nvd_df = None
    
    # Process CVE List V5
    print("\n[2/3] Processing CVE List V5...")
    try:
        cvelist_df = parse_cvelistv5()
        cvelist_df.to_parquet(OUTPUT_DIR / "cvelist_v5.parquet", index=False)
        cvelist_df.to_csv(OUTPUT_DIR / "cvelist_v5.csv", index=False)
        print(f"Saved CVE V5 data to {OUTPUT_DIR}/cvelist_v5.parquet")
        
        # CNA analysis
        cna_stats = analyze_cnas(cvelist_df)
        cna_stats.to_csv(OUTPUT_DIR / "cna_stats.csv")
        print(f"Saved CNA stats to {OUTPUT_DIR}/cna_stats.csv")
    except Exception as e:
        print(f"Error processing CVE List V5: {e}")
        cvelist_df = None
    
    # Summary statistics
    print("\n[3/3] Generating summary statistics...")
    print("\n" + "="*60)
    print("DATA SUMMARY")
    print("="*60)
    
    if nvd_df is not None:
        print(f"\nNVD Data:")
        print(f"  Total CVEs: {len(nvd_df):,}")
        print(f"  Year range: {nvd_df['year'].min()} - {nvd_df['year'].max()}")
        print(f"  2025 CVEs: {len(nvd_df[nvd_df['year'] == 2025]):,}")
        print(f"  With CVSS v3: {nvd_df['cvss_v3'].notna().sum():,}")
        print(f"  With CVSS v4: {nvd_df['cvss_v4'].notna().sum():,}")
        print(f"  With CWE: {nvd_df['cwe'].notna().sum():,}")
        print(f"  With CPE: {nvd_df['has_cpe'].sum():,}")
    
    if cvelist_df is not None:
        print(f"\nCVE List V5 Data:")
        print(f"  Total CVEs: {len(cvelist_df):,}")
        print(f"  Year range: {cvelist_df['year'].min()} - {cvelist_df['year'].max()}")
        print(f"  2025 CVEs: {len(cvelist_df[cvelist_df['year'] == 2025]):,}")
        print(f"  Published: {cvelist_df['is_published'].sum():,}")
        print(f"  Rejected: {cvelist_df['is_rejected'].sum():,}")
        print(f"  Unique CNAs: {cvelist_df['assigner_short_name'].nunique():,}")
    
    print("\n" + "="*60)
    print("Processing complete! Run 03_generate_graphs.py next.")
    print("="*60)

if __name__ == "__main__":
    main()
