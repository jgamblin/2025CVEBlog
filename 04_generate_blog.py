#!/usr/bin/env python3
"""
Generate 2025 CVE Data Review Blog Post
Creates a publishable Markdown blog with all visualizations

This script imports graph generation functions from 03_generate_graphs.py
to avoid code duplication and ensure consistent styling.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import warnings
import json
import importlib.util

warnings.filterwarnings('ignore')

# Import unified styling from style_config
from style_config import COLORS, SEVERITY_COLORS, CWE_NAMES

# Directories
OUTPUT_DIR = Path("processed")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)

# Import graph generation functions - using importlib for numeric filename
spec = importlib.util.spec_from_file_location("generate_graphs", "03_generate_graphs.py")
if spec is None or spec.loader is None:
    raise ImportError("Could not load 03_generate_graphs.py")
graphs_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graphs_module)

# Re-export functions from graphs module for use in this script
graph_cves_by_year = graphs_module.graph_cves_by_year
graph_yoy_growth = graphs_module.graph_yoy_growth
graph_cumulative_growth = graphs_module.graph_cumulative_growth
graph_2025_monthly = graphs_module.graph_2025_monthly
graph_cvss_distribution = graphs_module.graph_cvss_distribution
graph_severity_breakdown = graphs_module.graph_severity_breakdown
graph_top_cwes = graphs_module.graph_top_cwes
graph_top_cnas = graphs_module.graph_top_cnas
graph_data_quality = graphs_module.graph_data_quality
graph_rejected_cves = graphs_module.graph_rejected_cves
graph_cve_states = graphs_module.graph_cve_states
graph_cve_id_ranges = graphs_module.graph_cve_id_ranges
graph_cvss_by_year = graphs_module.graph_cvss_by_year
graph_top_vendors = graphs_module.graph_top_vendors
graph_time_to_publish = graphs_module.graph_time_to_publish
graph_day_of_week = graphs_module.graph_day_of_week
graph_top_days = graphs_module.graph_top_days
graph_top_products = graphs_module.graph_top_products
normalize_data = graphs_module.normalize_data


# =============================================================================
# DATA LOADING
# =============================================================================
def load_data():
    """Load processed data, returning both filtered and full datasets"""
    print("Loading processed data...")
    
    nvd_df = None
    cvelist_df = None
    
    if (OUTPUT_DIR / "nvd_cves.parquet").exists():
        nvd_df = pd.read_parquet(OUTPUT_DIR / "nvd_cves.parquet")
        print(f"  ✓ Loaded NVD data: {len(nvd_df):,} CVEs")
    elif (OUTPUT_DIR / "nvd_cves.csv").exists():
        nvd_df = pd.read_csv(OUTPUT_DIR / "nvd_cves.csv", parse_dates=['published', 'modified'])
        print(f"  ✓ Loaded NVD data: {len(nvd_df):,} CVEs")
    
    if (OUTPUT_DIR / "cvelist_v5.parquet").exists():
        cvelist_df = pd.read_parquet(OUTPUT_DIR / "cvelist_v5.parquet")
        print(f"  ✓ Loaded CVE List V5 data: {len(cvelist_df):,} CVEs")
    elif (OUTPUT_DIR / "cvelist_v5.csv").exists():
        cvelist_df = pd.read_csv(OUTPUT_DIR / "cvelist_v5.csv", parse_dates=['date_reserved', 'date_published'])
        print(f"  ✓ Loaded CVE List V5 data: {len(cvelist_df):,} CVEs")
    
    # Keep full datasets for rejection analysis
    full_nvd_df = nvd_df.copy() if nvd_df is not None else None
    full_cvelist_df = cvelist_df.copy() if cvelist_df is not None else None
    
    # Filter out rejected CVEs for the main analysis
    if nvd_df is not None and 'is_rejected' in nvd_df.columns:
        rejected_count = nvd_df['is_rejected'].sum()
        print(f"  → Filtering out {rejected_count:,} rejected CVEs from NVD data")
        nvd_df = nvd_df[~nvd_df['is_rejected']].copy()
    
    if cvelist_df is not None and 'is_rejected' in cvelist_df.columns:
        rejected_count = cvelist_df['is_rejected'].sum()
        print(f"  → Filtering out {rejected_count:,} rejected CVEs from CVE List V5")
        cvelist_df = cvelist_df[~cvelist_df['is_rejected']].copy()
    
    # STRICT 2025 CUTOFF: Exclude any data from 2026+
    if nvd_df is not None and 'year' in nvd_df.columns:
        future_count = (nvd_df['year'] > 2025).sum()
        if future_count > 0:
            print(f"  → Excluding {future_count:,} CVEs from 2026+ (strict 2025 cutoff)")
            nvd_df = nvd_df[nvd_df['year'] <= 2025].copy()
    
    if cvelist_df is not None and 'year' in cvelist_df.columns:
        future_count = (cvelist_df['year'] > 2025).sum()
        if future_count > 0:
            print(f"  → Excluding {future_count:,} CVEs from 2026+ (strict 2025 cutoff)")
            cvelist_df = cvelist_df[cvelist_df['year'] <= 2025].copy()
    
    # Also apply cutoff to full datasets used for rejection analysis
    if full_nvd_df is not None and 'year' in full_nvd_df.columns:
        full_nvd_df = full_nvd_df[full_nvd_df['year'] <= 2025].copy()
    
    if full_cvelist_df is not None and 'year' in full_cvelist_df.columns:
        full_cvelist_df = full_cvelist_df[full_cvelist_df['year'] <= 2025].copy()
    
    # Return both filtered (active) and full datasets
    return nvd_df, cvelist_df, full_nvd_df, full_cvelist_df


# =============================================================================
# STATISTICS CALCULATION
# =============================================================================
def calculate_stats(df, cvelist_df, full_nvd_df=None, full_cvelist_df=None):
    """Calculate all statistics for the blog"""
    stats = {}
    
    df_2025 = df[df['year'] == 2025]
    df_2024 = df[df['year'] == 2024]
    
    stats['total_2025'] = len(df_2025)
    stats['total_2024'] = len(df_2024)
    stats['total_all_time'] = len(df)
    stats['yoy_change'] = ((stats['total_2025'] - stats['total_2024']) / stats['total_2024'] * 100) if stats['total_2024'] > 0 else 0
    
    # Rejected CVE statistics (from full datasets)
    stats['rejected_2025'] = 0
    stats['rejected_all_time'] = 0
    if full_nvd_df is not None and 'is_rejected' in full_nvd_df.columns:
        stats['rejected_all_time'] = full_nvd_df['is_rejected'].sum()
        stats['rejected_2025'] = full_nvd_df[(full_nvd_df['year'] == 2025) & (full_nvd_df['is_rejected'])].shape[0]
    elif full_cvelist_df is not None and 'is_rejected' in full_cvelist_df.columns:
        stats['rejected_all_time'] = full_cvelist_df['is_rejected'].sum()
        stats['rejected_2025'] = full_cvelist_df[(full_cvelist_df['year'] == 2025) & (full_cvelist_df['is_rejected'])].shape[0]
    
    # Calculate rejection rate
    total_with_rejected_2025 = stats['total_2025'] + stats['rejected_2025']
    stats['rejection_rate_2025'] = (stats['rejected_2025'] / total_with_rejected_2025 * 100) if total_with_rejected_2025 > 0 else 0
    
    # Severity
    if 'severity' in df_2025.columns:
        severity_counts = df_2025['severity'].str.upper().value_counts()
        stats['critical'] = severity_counts.get('CRITICAL', 0)
        stats['high'] = severity_counts.get('HIGH', 0)
        stats['medium'] = severity_counts.get('MEDIUM', 0)
        stats['low'] = severity_counts.get('LOW', 0)
    else:
        stats['critical'] = stats['high'] = stats['medium'] = stats['low'] = 0
    
    # CVSS
    cvss_col = 'cvss_v3' if 'cvss_v3' in df.columns else 'cvss_v4'
    if cvss_col in df_2025.columns:
        stats['avg_cvss'] = df_2025[cvss_col].mean()
        stats['median_cvss'] = df_2025[cvss_col].median()
        stats['cvss_coverage'] = df_2025[cvss_col].notna().sum() / len(df_2025) * 100
    else:
        stats['avg_cvss'] = stats['median_cvss'] = stats['cvss_coverage'] = 0
    
    # CWE
    if 'cwe' in df_2025.columns:
        stats['cwe_coverage'] = df_2025['cwe'].notna().sum() / len(df_2025) * 100
        stats['top_cwe'] = df_2025['cwe'].value_counts().index[0] if df_2025['cwe'].notna().any() else 'N/A'
        stats['top_cwe_count'] = df_2025['cwe'].value_counts().iloc[0] if df_2025['cwe'].notna().any() else 0
    else:
        stats['cwe_coverage'] = 0
        stats['top_cwe'] = 'N/A'
        stats['top_cwe_count'] = 0
    
    # CPE
    if 'has_cpe' in df_2025.columns:
        stats['cpe_coverage'] = df_2025['has_cpe'].sum() / len(df_2025) * 100
    else:
        stats['cpe_coverage'] = 0
    
    # Yearly data
    yearly = df.groupby('year').size().reset_index(name='count')
    yearly = yearly[(yearly['year'] >= 1999) & (yearly['year'] <= 2025)]
    stats['yearly'] = yearly
    
    # CVE List V5 specific stats
    if cvelist_df is not None:
        cv_2025 = cvelist_df[cvelist_df['year'] == 2025]
        
        if 'assigner_short_name' in cv_2025.columns:
            stats['unique_cnas'] = cv_2025['assigner_short_name'].nunique()
            cna_counts = cv_2025['assigner_short_name'].value_counts()
            stats['top_cna'] = cna_counts.index[0] if len(cna_counts) > 0 else 'N/A'
            stats['top_cna_count'] = cna_counts.iloc[0] if len(cna_counts) > 0 else 0
        
        if 'state' in cv_2025.columns:
            state_counts = cv_2025['state'].value_counts()
            stats['published'] = state_counts.get('PUBLISHED', 0)
            stats['rejected'] = state_counts.get('REJECTED', 0)
            stats['reserved'] = state_counts.get('RESERVED', 0)
        
        if 'vendor' in cv_2025.columns:
            stats['unique_vendors'] = cv_2025['vendor'].nunique()
    
    return stats


# =============================================================================
# BLOG GENERATION
# =============================================================================
def generate_blog(stats, top_cwes, top_cnas, top_vendors, peak_month, peak_count, cumulative_total, rejected_stats=None, day_stats=None, top_days=None, top_products=None):
    """Generate the Markdown blog post"""
    
    blog = f"""# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

Another year, another record-breaking year for CVE disclosures. In this annual review, I analyze the Common Vulnerabilities and Exposures (CVE) data for 2025, examining trends in vulnerability disclosures, severity distributions, and the organizations driving vulnerability documentation.

## TL;DR

**2025 saw {stats['total_2025']:,} CVEs published**, {'an increase' if stats['yoy_change'] > 0 else 'a decrease'} of **{abs(stats['yoy_change']):.1f}%** compared to {stats['total_2024']:,} CVEs in 2024. This brings the all-time total to **{stats['total_all_time']:,} CVEs** since the program began in 1999.

> **Note**: All statistics in this report exclude rejected CVEs to provide an accurate count of active vulnerabilities.

### Key Statistics at a Glance

| Metric | Value |
|--------|-------|
| **Total CVEs in 2025** | **{stats['total_2025']:,}** |
| Year-over-Year Change | {stats['yoy_change']:+.1f}% |
| Critical Severity | {stats['critical']:,} |
| High Severity | {stats['high']:,} |
| Average CVSS Score | {stats['avg_cvss']:.2f} |
| CVSS Coverage | {stats['cvss_coverage']:.1f}% |
| CWE Coverage | {stats['cwe_coverage']:.1f}% |
"""

    if 'unique_cnas' in stats:
        blog += f"| Active CNAs | {stats['unique_cnas']:,} |\n"
    
    if stats.get('rejected_2025', 0) > 0:
        blog += f"| Rejected CVEs (2025) | {stats['rejected_2025']:,} |\n"
    
    blog += f"""
---

## Historical CVE Growth

The number of CVEs published each year continues its upward trajectory. 2025 marks another year of significant growth in vulnerability disclosures.

![CVEs by Year](graphs/01_cves_by_year.png)

The growth isn't uniform—some years saw dramatic increases while others showed modest growth or even slight declines. The year-over-year growth rate provides a clearer picture of these fluctuations.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

Looking at the cumulative total, we've now surpassed **{cumulative_total:,} CVEs** in the database.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---

## 2025 Monthly Distribution

"""

    if peak_month and peak_count:
        blog += f"""CVE publications varied throughout 2025, with **{peak_month}** being the peak month at **{peak_count:,} CVEs**.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

---
"""

    # Day of Week Analysis (Patch Tuesday effect)
    if day_stats:
        blog += f"""
## Publication Patterns by Day of Week

Looking at which days CVEs are published reveals interesting patterns. **{day_stats['peak_day']}** saw the most publications with **{day_stats['peak_count']:,} CVEs**.

![CVEs by Day of Week](graphs/16_day_of_week.png)

The "Patch Tuesday" effect is visible: Tuesday accounts for **{day_stats['tuesday_count']:,} CVEs**. Weekdays average **{day_stats['weekday_avg']:,.0f}** CVEs compared to weekends at **{day_stats['weekend_avg']:,.0f}**.

---
"""

    # Top Days
    if top_days and len(top_days) > 0:
        blog += """
## Busiest Days of 2025

Some days saw massive spikes in CVE publications:

![Top Days](graphs/17_top_days.png)

### Top 5 Busiest Days

| Rank | Date | CVE Count |
|------|------|----------|
"""
        for i, (date, count) in enumerate(top_days[:5], 1):
            blog += f"| {i} | {date} | {count:,} |\n"
        blog += "\n---\n"

    # Top Products
    if top_products and len(top_products) > 0:
        blog += """
## Most Vulnerable Products

Beyond vendors, specific products with the most CVEs in 2025:

![Top Products](graphs/18_top_products.png)

### Top 5 Products

| Rank | Product | CVE Count |
|------|---------|----------|
"""
        for i, (product, count) in enumerate(top_products[:5], 1):
            blog += f"| {i} | {product} | {count:,} |\n"
        blog += "\n---\n"

    blog += f"""
## CVSS Score Analysis

The Common Vulnerability Scoring System (CVSS) helps standardize severity assessments. Here's how 2025 CVEs were distributed across the scoring range.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The **average CVSS score for 2025 was {stats['avg_cvss']:.2f}**, with a **median of {stats['median_cvss']:.2f}**.

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {stats['critical']:,} | {stats['critical']/stats['total_2025']*100:.1f}% |
| High | {stats['high']:,} | {stats['high']/stats['total_2025']*100:.1f}% |
| Medium | {stats['medium']:,} | {stats['medium']/stats['total_2025']*100:.1f}% |
| Low | {stats['low']:,} | {stats['low']/stats['total_2025']*100:.1f}% |

![Severity Breakdown](graphs/06_severity_breakdown.png)

### CVSS Trends Over Time

![CVSS by Year](graphs/13_cvss_by_year.png)

---

## Top Weakness Types (CWE)

The Common Weakness Enumeration (CWE) categorizes the types of security weaknesses. Here are the most prevalent weakness types in 2025:

![Top CWEs](graphs/07_top_cwes.png)

### Top 5 CWEs in 2025

| Rank | CWE | Name | Count |
|------|-----|------|-------|
"""

    for i, (cwe, count) in enumerate(top_cwes, 1):
        name = CWE_NAMES.get(cwe, '')
        blog += f"| {i} | {cwe} | {name} | {count:,} |\n"

    blog += """
---

## CVE Numbering Authorities (CNAs)

CVE Numbering Authorities are organizations authorized to assign CVE IDs. The ecosystem continues to grow with more organizations participating in coordinated vulnerability disclosure.

![Top CNAs](graphs/08_top_cnas.png)

### Top 5 CNAs in 2025

| Rank | CNA | CVEs Assigned |
|------|-----|---------------|
"""

    for i, (cna, count) in enumerate(top_cnas, 1):
        blog += f"| {i} | {cna} | {count:,} |\n"

    if 'unique_cnas' in stats:
        blog += f"\nIn total, **{stats['unique_cnas']} unique CNAs** assigned CVEs in 2025.\n"

    blog += """
---

## Top Vendors

Which vendors had the most CVEs assigned to their products in 2025?

![Top Vendors](graphs/14_top_vendors.png)

### Top 5 Vendors in 2025

| Rank | Vendor | CVE Count |
|------|--------|-----------|
"""

    for i, (vendor, count) in enumerate(top_vendors, 1):
        blog += f"| {i} | {vendor} | {count:,} |\n"

    blog += f"""
---

## Data Quality

Not all CVEs have complete metadata. Here's how data quality has evolved over the years:

![Data Quality](graphs/09_data_quality.png)

### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | {stats['cvss_coverage']:.1f}% |
| CWE Classification | {stats['cwe_coverage']:.1f}% |
| CPE Identifiers | {stats['cpe_coverage']:.1f}% |

---

## Rejected CVEs

Not all CVE IDs remain active—some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the CVE ecosystem's quality control.

"""
    
    if rejected_stats:
        blog += f"""![Rejected CVEs](graphs/10_rejected_cves.png)

### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | {rejected_stats['rejected_2025']:,} |
| 2025 Rejection Rate | {rejected_stats['rate_2025']:.2f}% |
| Total Rejected (All Time) | {rejected_stats['total_rejected']:,} |

CVE rejections occur for several reasons:
- **Duplicates**: The same vulnerability assigned multiple CVE IDs
- **Disputes**: Vendor disagreement that the issue is a vulnerability  
- **Invalid**: Not a security vulnerability or insufficient information
- **Withdrawn**: CVE withdrawn by the assigning CNA

"""
    else:
        blog += """*Rejection data analysis unavailable.*

"""

    blog += f"""---

## Conclusions

### Key Takeaways from 2025

1. **Volume continues to grow**: With {stats['total_2025']:,} CVEs, 2025 {'set a new record' if stats['yoy_change'] > 0 else 'saw a slight decline'} in vulnerability disclosures.

2. **Severity remains concerning**: {stats['critical'] + stats['high']:,} CVEs ({(stats['critical'] + stats['high'])/stats['total_2025']*100:.1f}%) were rated Critical or High severity.

3. **Common weaknesses persist**: Memory safety issues and web application vulnerabilities continue to dominate the top CWE list.

4. **Ecosystem expansion**: The growing number of CNAs reflects broader participation in coordinated vulnerability disclosure.

5. **Data quality challenges**: While improving, a significant portion of CVEs still lack complete CVSS, CWE, or CPE data.

---

## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*
"""

    return blog


# =============================================================================
# MAIN
# =============================================================================
def main():
    print("=" * 60)
    print("2025 CVE Data Review - Blog Generator")
    print("=" * 60)
    
    # Load data (returns both filtered and full datasets)
    nvd_df, cvelist_df, full_nvd_df, full_cvelist_df = load_data()
    
    if nvd_df is None and cvelist_df is None:
        print("\nERROR: No data found. Run these scripts first:")
        print("  1. python 01_download_data.py")
        print("  2. python 02_process_data.py")
        return
    
    # NORMALIZE DATA - Clean and deduplicate before analysis
    nvd_df = normalize_data(nvd_df)
    cvelist_df = normalize_data(cvelist_df)
    
    # Use NVD as primary, CVE List V5 as secondary
    df = nvd_df if nvd_df is not None else cvelist_df
    full_df = full_nvd_df if full_nvd_df is not None else full_cvelist_df
    
    if df is None:
        print("\nERROR: No valid data loaded.")
        return
    
    print(f"\nUsing primary dataset: {len(df):,} active CVEs (excluded rejected)")
    
    # Calculate statistics
    print("\nCalculating statistics...")
    stats = calculate_stats(df, cvelist_df, full_nvd_df, full_cvelist_df)
    
    # Generate all graphs using imported functions from 03_generate_graphs.py
    print("\nGenerating graphs...")
    
    # CVEs by Year - returns (fig, yearly_data)
    _, yearly_data = graph_cves_by_year(df, save_path=GRAPHS_DIR / '01_cves_by_year.png')
    
    # YoY Growth
    graph_yoy_growth(yearly_data, save_path=GRAPHS_DIR / '02_yoy_growth.png')
    
    # Cumulative Growth - returns (fig, cumulative_total)
    _, cumulative_total = graph_cumulative_growth(yearly_data, save_path=GRAPHS_DIR / '03_cumulative_growth.png')
    
    # 2025 Monthly - returns (fig, peak_month, peak_count)
    _, peak_month, peak_count = graph_2025_monthly(df, save_path=GRAPHS_DIR / '04_2025_monthly.png')
    
    # CVSS Distribution
    graph_cvss_distribution(df, save_path=GRAPHS_DIR / '05_cvss_distribution.png')
    
    # Severity Breakdown
    graph_severity_breakdown(df, save_path=GRAPHS_DIR / '06_severity_breakdown.png')
    
    # Top CWEs - returns (fig, top_cwes_list)
    _, top_cwes = graph_top_cwes(df, save_path=GRAPHS_DIR / '07_top_cwes.png')
    if top_cwes is None:
        top_cwes = []
    
    # Data Quality
    graph_data_quality(df, save_path=GRAPHS_DIR / '09_data_quality.png')
    
    # CVSS by Year
    graph_cvss_by_year(df, save_path=GRAPHS_DIR / '13_cvss_by_year.png')
    
    # Rejected CVE analysis (uses full dataset) - returns (fig, rejected_stats)
    rejected_stats = None
    if full_df is not None:
        result = graph_rejected_cves(full_df, save_path=GRAPHS_DIR / '10_rejected_cves.png')
        if result is not None:
            _, rejected_stats = result
    
    # CVE List V5 specific graphs
    cna_df = cvelist_df if cvelist_df is not None else df
    
    # Top CNAs - returns (fig, top_cnas_list)
    _, top_cnas = graph_top_cnas(cna_df, save_path=GRAPHS_DIR / '08_top_cnas.png')
    if top_cnas is None:
        top_cnas = []
    
    # Top Vendors - returns (fig, top_vendors_list)
    _, top_vendors = graph_top_vendors(cna_df, save_path=GRAPHS_DIR / '14_top_vendors.png')
    if top_vendors is None:
        top_vendors = []
    
    # Day of Week Analysis - returns (fig, day_stats_dict)
    _, day_stats = graph_day_of_week(df, save_path=GRAPHS_DIR / '16_day_of_week.png')
    
    # Top Days Analysis - returns (fig, top_days_list)
    _, top_days = graph_top_days(df, save_path=GRAPHS_DIR / '17_top_days.png')
    if top_days is None:
        top_days = []
    
    # Top Products Analysis - returns (fig, top_products_list)
    _, top_products = graph_top_products(df, save_path=GRAPHS_DIR / '18_top_products.png')
    if top_products is None:
        top_products = []
    
    # Generate blog
    print("\nGenerating blog.md...")
    blog_content = generate_blog(stats, top_cwes, top_cnas, top_vendors, 
                                  peak_month, peak_count, cumulative_total, rejected_stats,
                                  day_stats, top_days, top_products)
    
    with open('blog.md', 'w') as f:
        f.write(blog_content)
    
    print("\n" + "=" * 60)
    print("COMPLETE!")
    print("=" * 60)
    print(f"\n✓ Blog saved to: blog.md")
    print(f"✓ Graphs saved to: {GRAPHS_DIR}/")
    print(f"\nGenerated {len(list(GRAPHS_DIR.glob('*.png')))} graphs")
    print("\nYou can now publish blog.md!")


if __name__ == "__main__":
    main()
