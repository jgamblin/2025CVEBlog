#!/usr/bin/env python3
"""
Generate 2025 CVE Data Review Blog Post
Creates a publishable Markdown blog with all visualizations
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
from pathlib import Path
from datetime import datetime
import warnings
import json

warnings.filterwarnings('ignore')

# =============================================================================
# GRAPH STYLING CONFIGURATION - Consistent across all graphs
# =============================================================================

# Standard figure sizes
FIG_SIZE_WIDE = (14, 7)      # For bar charts, line charts
FIG_SIZE_TALL = (14, 10)     # For horizontal bar charts with many items
FIG_SIZE_DOUBLE = (16, 7)    # For side-by-side charts

# Font sizes
TITLE_SIZE = 18
LABEL_SIZE = 14
TICK_SIZE = 11
ANNOTATION_SIZE = 10
LEGEND_SIZE = 11

# DPI for saving
SAVE_DPI = 300

# Set global style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': TICK_SIZE,
    'axes.titlesize': TITLE_SIZE,
    'axes.labelsize': LABEL_SIZE,
    'xtick.labelsize': TICK_SIZE,
    'ytick.labelsize': TICK_SIZE,
    'legend.fontsize': LEGEND_SIZE,
    'figure.titlesize': TITLE_SIZE,
    'axes.titleweight': 'bold',
    'axes.labelweight': 'bold',
})

# Directories
OUTPUT_DIR = Path("processed")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)

# Color scheme - Consistent palette across all graphs
COLORS = {
    'primary': '#2563eb',      # Blue - main data
    'secondary': '#7c3aed',    # Purple - secondary data
    'success': '#059669',      # Green - positive/growth
    'warning': '#d97706',      # Orange - caution
    'danger': '#dc2626',       # Red - highlight/current year
    'info': '#0891b2',         # Teal - vendor/info
    'gray': '#6b7280',         # Gray - neutral
    'muted': '#94a3b8',        # Light gray - background elements
}

SEVERITY_COLORS = {
    'CRITICAL': '#7f1d1d',     # Dark red
    'HIGH': '#dc2626',         # Red
    'MEDIUM': '#f59e0b',       # Orange/Amber
    'LOW': '#22c55e',          # Green
    'NONE': '#9ca3af'          # Gray
}

# CWE names mapping
CWE_NAMES = {
    'CWE-79': 'Cross-site Scripting (XSS)',
    'CWE-89': 'SQL Injection',
    'CWE-787': 'Out-of-bounds Write',
    'CWE-125': 'Out-of-bounds Read',
    'CWE-20': 'Improper Input Validation',
    'CWE-22': 'Path Traversal',
    'CWE-352': 'Cross-Site Request Forgery',
    'CWE-78': 'OS Command Injection',
    'CWE-416': 'Use After Free',
    'CWE-190': 'Integer Overflow',
    'CWE-476': 'NULL Pointer Dereference',
    'CWE-119': 'Buffer Overflow',
    'CWE-200': 'Information Exposure',
    'CWE-400': 'Resource Exhaustion',
    'CWE-434': 'Unrestricted File Upload',
    'CWE-863': 'Incorrect Authorization',
    'CWE-918': 'Server-Side Request Forgery',
    'CWE-94': 'Code Injection',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-287': 'Improper Authentication',
    'CWE-269': 'Improper Privilege Management',
    'CWE-77': 'Command Injection',
    'CWE-276': 'Incorrect Default Permissions',
    'CWE-862': 'Missing Authorization',
    'CWE-121': 'Stack-based Buffer Overflow',
    'NVD-CWE-noinfo': 'No CWE Information',
    'NVD-CWE-Other': 'Other'
}

def format_thousands(x, pos):
    """Format axis labels with K suffix"""
    if x >= 1000:
        return f'{int(x/1000)}K'
    return f'{int(x)}'

def load_data():
    """Load processed data"""
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
    
    # Filter out rejected CVEs for the main analysis
    if nvd_df is not None and 'is_rejected' in nvd_df.columns:
        rejected_count = nvd_df['is_rejected'].sum()
        print(f"  → Filtering out {rejected_count:,} rejected CVEs from NVD data")
        nvd_df_active = nvd_df[~nvd_df['is_rejected']].copy()
    else:
        nvd_df_active = nvd_df
    
    if cvelist_df is not None and 'is_rejected' in cvelist_df.columns:
        rejected_count = cvelist_df['is_rejected'].sum()
        print(f"  → Filtering out {rejected_count:,} rejected CVEs from CVE List V5")
        cvelist_df_active = cvelist_df[~cvelist_df['is_rejected']].copy()
    else:
        cvelist_df_active = cvelist_df
    
    # Return both filtered (active) and full datasets
    return nvd_df_active, cvelist_df_active, nvd_df, cvelist_df

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
# GRAPH GENERATION FUNCTIONS
# =============================================================================

def graph_cves_by_year(df):
    """Bar chart showing CVEs by year"""
    print("  Generating: CVEs by Year...")
    
    yearly = df.groupby('year').size().reset_index(name='count')
    yearly = yearly[(yearly['year'] >= 1999) & (yearly['year'] <= 2025)]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    bars = ax.bar(yearly['year'], yearly['count'], color=COLORS['primary'], 
                  edgecolor='white', linewidth=0.5)
    
    # Highlight 2025
    if 2025 in yearly['year'].values:
        bars[yearly['year'].tolist().index(2025)].set_color(COLORS['danger'])
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('CVEs Published by Year (1999-2025)', pad=20)
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    ax.set_xticks(yearly['year'])
    ax.set_xticklabels(yearly['year'], rotation=45, ha='right')
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height):,}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, rotation=90)
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '01_cves_by_year.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    return yearly

def graph_yoy_growth(yearly_data):
    """Line chart showing year-over-year growth rate"""
    print("  Generating: Year-over-Year Growth...")
    
    yearly = yearly_data.copy()
    yearly['yoy_change'] = yearly['count'].pct_change() * 100
    yearly = yearly[yearly['year'] >= 2000]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    colors = [COLORS['success'] if x >= 0 else COLORS['danger'] for x in yearly['yoy_change']]
    ax.bar(yearly['year'], yearly['yoy_change'], color=colors, 
           edgecolor='white', linewidth=0.5, alpha=0.85)
    ax.axhline(y=0, color='black', linestyle='-', linewidth=1)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Year-over-Year Change (%)')
    ax.set_title('CVE Year-over-Year Growth Rate (2000-2025)', pad=20)
    
    ax.set_xticks(yearly['year'])
    ax.set_xticklabels(yearly['year'].astype(int), rotation=45, ha='right')
    
    # Add value labels
    for year, val in zip(yearly['year'], yearly['yoy_change']):
        if pd.notna(val):
            ax.annotate(f'{val:.1f}%',
                        xy=(year, val),
                        xytext=(0, 5 if val >= 0 else -15),
                        textcoords="offset points",
                        ha='center', va='bottom' if val >= 0 else 'top', 
                        fontsize=ANNOTATION_SIZE - 2)
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '02_yoy_growth.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()

def graph_cumulative_growth(yearly_data):
    """Line chart showing cumulative CVE count"""
    print("  Generating: Cumulative Growth...")
    
    yearly = yearly_data.copy()
    yearly['cumulative'] = yearly['count'].cumsum()
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    ax.fill_between(yearly['year'], yearly['cumulative'], alpha=0.3, color=COLORS['primary'])
    ax.plot(yearly['year'], yearly['cumulative'], color=COLORS['primary'], 
            linewidth=3, marker='o', markersize=5)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Cumulative CVEs')
    ax.set_title('Cumulative CVE Count Over Time', pad=20)
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    # Add milestone lines
    milestones = [50000, 100000, 150000, 200000, 250000, 300000]
    for milestone in milestones:
        if yearly['cumulative'].max() >= milestone:
            ax.axhline(y=milestone, color=COLORS['muted'], linestyle='--', alpha=0.5)
            ax.annotate(f'{milestone//1000}K', xy=(yearly['year'].min() + 1, milestone), 
                       fontsize=ANNOTATION_SIZE, color=COLORS['gray'], va='bottom')
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '03_cumulative_growth.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    return yearly['cumulative'].iloc[-1]

def graph_2025_monthly(df):
    """Bar chart showing 2025 CVEs by month"""
    print("  Generating: 2025 Monthly Distribution...")
    
    df_2025 = df[df['year'] == 2025].copy()
    
    if 'published' in df_2025.columns:
        df_2025['month'] = pd.to_datetime(df_2025['published']).dt.month
    elif 'date_published' in df_2025.columns:
        df_2025['month'] = pd.to_datetime(df_2025['date_published']).dt.month
    else:
        return None, None
    
    monthly = df_2025.groupby('month').size().reindex(range(1, 13), fill_value=0)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    bars = ax.bar(month_names, monthly.values, color=COLORS['primary'], edgecolor='white')
    
    # Highlight the peak month and December (current)
    peak_idx = monthly.argmax()
    bars[peak_idx].set_color(COLORS['danger'])
    if peak_idx != 11:  # If peak is not December
        bars[11].set_color(COLORS['warning'])  # Highlight December differently
    
    ax.set_xlabel('Month')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVEs by Month', pad=20)
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(f'{int(height):,}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=ANNOTATION_SIZE, fontweight='bold')
    
    # Add average line
    avg = monthly.mean()
    ax.axhline(y=avg, color=COLORS['danger'], linestyle='--', linewidth=2, 
               label=f'Monthly Average: {avg:,.0f}')
    ax.legend(fontsize=LEGEND_SIZE)
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '04_2025_monthly.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    peak_month = month_names[monthly.argmax()]
    return peak_month, monthly.max()

def graph_cvss_distribution(df):
    """Histogram of CVSS scores"""
    print("  Generating: CVSS Score Distribution...")
    
    cvss_col = 'cvss_v3' if 'cvss_v3' in df.columns else 'cvss_v4'
    df_2025 = df[(df['year'] == 2025) & (df[cvss_col].notna())].copy()
    
    if len(df_2025) == 0:
        return
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    bins = np.arange(0, 10.5, 0.5)
    n, bins_edges, patches = ax.hist(df_2025[cvss_col], bins=bins, edgecolor='white', linewidth=0.5)
    
    # Color by severity
    for i, patch in enumerate(patches):
        score = (bins_edges[i] + bins_edges[i+1]) / 2
        if score >= 9.0:
            patch.set_facecolor(SEVERITY_COLORS['CRITICAL'])
        elif score >= 7.0:
            patch.set_facecolor(SEVERITY_COLORS['HIGH'])
        elif score >= 4.0:
            patch.set_facecolor(SEVERITY_COLORS['MEDIUM'])
        else:
            patch.set_facecolor(SEVERITY_COLORS['LOW'])
    
    ax.set_xlabel('CVSS Score')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVE CVSS Score Distribution', pad=20)
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=SEVERITY_COLORS['CRITICAL'], label='Critical (9.0-10.0)'),
        Patch(facecolor=SEVERITY_COLORS['HIGH'], label='High (7.0-8.9)'),
        Patch(facecolor=SEVERITY_COLORS['MEDIUM'], label='Medium (4.0-6.9)'),
        Patch(facecolor=SEVERITY_COLORS['LOW'], label='Low (0.1-3.9)')
    ]
    ax.legend(handles=legend_elements, loc='upper left', fontsize=LEGEND_SIZE)
    
    # Add mean/median lines
    mean_score = df_2025[cvss_col].mean()
    median_score = df_2025[cvss_col].median()
    ax.axvline(x=mean_score, color=COLORS['primary'], linestyle='--', linewidth=2, alpha=0.7)
    ax.axvline(x=median_score, color=COLORS['secondary'], linestyle='--', linewidth=2, alpha=0.7)
    
    # Stats box
    textstr = f'Mean: {mean_score:.2f}\nMedian: {median_score:.2f}\nTotal: {len(df_2025):,}'
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=ANNOTATION_SIZE + 1,
            verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '05_cvss_distribution.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()


def graph_severity_breakdown(df):
    """Pie chart of severity distribution"""
    print("  Generating: Severity Breakdown...")
    
    df_2025 = df[(df['year'] == 2025) & (df['severity'].notna())].copy()
    
    if len(df_2025) == 0:
        return
    
    severity_counts = df_2025['severity'].str.upper().value_counts()
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
    severity_counts = severity_counts.reindex(severity_order).dropna()
    
    colors = [SEVERITY_COLORS.get(s, COLORS['gray']) for s in severity_counts.index]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIG_SIZE_DOUBLE)
    
    # Pie chart
    wedges, texts, autotexts = ax1.pie(
        severity_counts, labels=severity_counts.index, 
        autopct='%1.1f%%', colors=colors,
        explode=[0.05 if s == 'CRITICAL' else 0 for s in severity_counts.index],
        textprops={'fontsize': TICK_SIZE}
    )
    for autotext in autotexts:
        autotext.set_fontsize(ANNOTATION_SIZE)
    ax1.set_title('2025 CVE Severity Distribution', fontsize=TITLE_SIZE - 2, fontweight='bold')
    
    # Horizontal bar chart
    bars = ax2.barh(severity_counts.index[::-1], severity_counts.values[::-1], 
                    color=[SEVERITY_COLORS.get(s, COLORS['gray']) for s in severity_counts.index[::-1]],
                    edgecolor='white')
    ax2.set_xlabel('Number of CVEs')
    ax2.set_title('2025 CVEs by Severity', fontsize=TITLE_SIZE - 2, fontweight='bold')
    
    # Add value labels
    for bar in bars:
        width = bar.get_width()
        ax2.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, fontweight='bold')
    
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '06_severity_breakdown.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()

def graph_top_cwes(df, top_n=15):
    """Bar chart of most common CWEs"""
    print("  Generating: Top CWEs...")
    
    df_2025 = df[(df['year'] == 2025) & (df['cwe'].notna())].copy()
    
    if len(df_2025) == 0:
        return []
    
    cwe_counts = df_2025['cwe'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(cwe_counts))
    bars = ax.barh(y_pos, cwe_counts.values, color=COLORS['primary'], edgecolor='white')
    
    # Create labels with CWE names
    labels = []
    for cwe in cwe_counts.index:
        name = CWE_NAMES.get(cwe, '')
        if name:
            labels.append(f"{cwe}\n{name}")
        else:
            labels.append(cwe)
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=TICK_SIZE - 1)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title(f'Top {top_n} CWEs in 2025 CVEs', pad=20)
    
    # Add value labels
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, fontweight='bold')
    
    ax.invert_yaxis()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '07_top_cwes.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    return list(zip(cwe_counts.index[:5], cwe_counts.values[:5]))

def graph_top_cnas(df, top_n=20):
    """Bar chart of most active CNAs"""
    print("  Generating: Top CNAs...")
    
    if 'assigner_short_name' not in df.columns:
        return []
    
    df_2025 = df[df['year'] == 2025].copy()
    cna_counts = df_2025['assigner_short_name'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(cna_counts))
    bars = ax.barh(y_pos, cna_counts.values, color=COLORS['secondary'], edgecolor='white')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(cna_counts.index, fontsize=TICK_SIZE)
    
    ax.set_xlabel('Number of CVEs Assigned')
    ax.set_title(f'Top {top_n} CVE Numbering Authorities (CNAs) in 2025', pad=20)
    
    # Add value labels
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, fontweight='bold')
    
    ax.invert_yaxis()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '08_top_cnas.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    return list(zip(cna_counts.index[:5], cna_counts.values[:5]))

def graph_data_quality(df):
    """Stacked bar chart showing data completeness"""
    print("  Generating: Data Quality Metrics...")
    
    df_recent = df[df['year'] >= 2015].copy()
    
    metrics = []
    for year in range(2015, 2026):
        year_df = df_recent[df_recent['year'] == year]
        total = len(year_df)
        if total == 0:
            continue
        
        has_cvss = year_df['cvss_v3'].notna().sum() if 'cvss_v3' in year_df.columns else 0
        has_cwe = year_df['cwe'].notna().sum() if 'cwe' in year_df.columns else 0
        has_cpe = year_df['has_cpe'].sum() if 'has_cpe' in year_df.columns else 0
        
        metrics.append({
            'year': year,
            'total': total,
            'cvss_pct': (has_cvss / total) * 100,
            'cwe_pct': (has_cwe / total) * 100,
            'cpe_pct': (has_cpe / total) * 100
        })
    
    metrics_df = pd.DataFrame(metrics)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    x = np.arange(len(metrics_df))
    width = 0.25
    
    ax.bar(x - width, metrics_df['cvss_pct'], width, label='Has CVSS', 
           color=COLORS['primary'], edgecolor='white')
    ax.bar(x, metrics_df['cwe_pct'], width, label='Has CWE', 
           color=COLORS['secondary'], edgecolor='white')
    ax.bar(x + width, metrics_df['cpe_pct'], width, label='Has CPE', 
           color=COLORS['success'], edgecolor='white')
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Percentage (%)')
    ax.set_title('CVE Data Quality Over Time\n(Percentage with CVSS, CWE, and CPE)', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_df['year'].astype(int))
    ax.legend(fontsize=LEGEND_SIZE)
    ax.set_ylim(0, 100)
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '09_data_quality.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()

def graph_top_vendors(df, top_n=20):
    """Bar chart of vendors with most CVEs"""
    print("  Generating: Top Vendors...")
    
    if 'vendor' not in df.columns:
        return []
    
    df_2025 = df[(df['year'] == 2025) & (df['vendor'].notna())].copy()
    df_2025['vendor_clean'] = df_2025['vendor'].str.lower().str.strip()
    vendor_counts = df_2025['vendor_clean'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(vendor_counts))
    bars = ax.barh(y_pos, vendor_counts.values, color=COLORS['info'], edgecolor='white')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(vendor_counts.index, fontsize=TICK_SIZE)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title(f'Top {top_n} Vendors by CVE Count in 2025', pad=20)
    
    # Add value labels
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, fontweight='bold')
    
    ax.invert_yaxis()
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '10_top_vendors.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    return list(zip(vendor_counts.index[:5], vendor_counts.values[:5]))

def graph_cvss_by_year(df):
    """Box plot comparing CVSS scores across years"""
    print("  Generating: CVSS by Year...")
    
    cvss_col = 'cvss_v3' if 'cvss_v3' in df.columns else 'cvss_v4'
    df_recent = df[(df['year'] >= 2018) & (df[cvss_col].notna())].copy()
    
    if len(df_recent) == 0:
        return
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_WIDE)
    
    years = sorted(df_recent['year'].unique())
    data = [df_recent[df_recent['year'] == y][cvss_col].values for y in years]
    
    bp = ax.boxplot(data, labels=years, patch_artist=True)
    
    # Color boxes - highlight 2025
    for i, box in enumerate(bp['boxes']):
        if years[i] == 2025:
            box.set_facecolor(COLORS['danger'])
        else:
            box.set_facecolor(COLORS['primary'])
        box.set_alpha(0.7)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('CVSS v3 Score')
    ax.set_title('CVSS Score Distribution by Year (2018-2025)', pad=20)
    
    # Severity threshold lines
    ax.axhline(y=9.0, color=SEVERITY_COLORS['CRITICAL'], linestyle='--', alpha=0.7, label='Critical (9.0+)')
    ax.axhline(y=7.0, color=SEVERITY_COLORS['HIGH'], linestyle='--', alpha=0.7, label='High (7.0+)')
    ax.axhline(y=4.0, color=SEVERITY_COLORS['MEDIUM'], linestyle='--', alpha=0.7, label='Medium (4.0+)')
    ax.legend(loc='lower right', fontsize=LEGEND_SIZE)
    
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '11_cvss_by_year.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()


def graph_rejected_cves(full_df):
    """Bar chart showing rejected CVEs by year"""
    print("  Generating: Rejected CVEs by Year...")
    
    if 'is_rejected' not in full_df.columns:
        return None
    
    # Get rejected CVEs by year
    rejected_by_year = full_df[full_df['is_rejected']].groupby('year').size()
    total_by_year = full_df.groupby('year').size()
    
    # Filter to recent years
    years = range(2015, 2026)
    rejected_counts = [rejected_by_year.get(y, 0) for y in years]
    total_counts = [total_by_year.get(y, 0) for y in years]
    rejection_rates = [(r/t*100 if t > 0 else 0) for r, t in zip(rejected_counts, total_counts)]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIG_SIZE_DOUBLE)
    
    # Left: Rejected count by year
    bars1 = ax1.bar(years, rejected_counts, color=COLORS['warning'], edgecolor='white')
    bars1[-1].set_color(COLORS['danger'])  # Highlight 2025
    
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Rejected CVEs')
    ax1.set_title('Rejected CVEs by Year', fontsize=TITLE_SIZE - 2, fontweight='bold')
    ax1.set_xticks(years)
    ax1.set_xticklabels(years, rotation=45, ha='right')
    
    for bar in bars1:
        height = bar.get_height()
        if height > 0:
            ax1.annotate(f'{int(height):,}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=ANNOTATION_SIZE - 1)
    
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    
    # Right: Rejection rate by year
    bars2 = ax2.bar(years, rejection_rates, color=COLORS['secondary'], edgecolor='white')
    bars2[-1].set_color(COLORS['danger'])  # Highlight 2025
    
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Rejection Rate (%)')
    ax2.set_title('CVE Rejection Rate by Year', fontsize=TITLE_SIZE - 2, fontweight='bold')
    ax2.set_xticks(years)
    ax2.set_xticklabels(years, rotation=45, ha='right')
    
    for bar in bars2:
        height = bar.get_height()
        if height > 0:
            ax2.annotate(f'{height:.1f}%',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=ANNOTATION_SIZE - 1)
    
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / '12_rejected_cves.png', dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    return {
        'rejected_2025': rejected_counts[-1],
        'rate_2025': rejection_rates[-1],
        'total_rejected': sum(rejected_counts)
    }

# =============================================================================
# BLOG GENERATION
# =============================================================================

def generate_blog(stats, top_cwes, top_cnas, top_vendors, peak_month, peak_count, cumulative_total, rejected_stats=None):
    """Generate the Markdown blog post"""
    
    blog = f"""# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

Another year, another record-breaking year for CVE disclosures. In this annual review, I analyze the Common Vulnerabilities and Exposures (CVE) data for 2025, examining trends in vulnerability disclosures, severity distributions, and the organizations driving vulnerability documentation.

## Executive Summary

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

![CVSS by Year](graphs/11_cvss_by_year.png)

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

![Top Vendors](graphs/10_top_vendors.png)

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
        blog += f"""![Rejected CVEs](graphs/12_rejected_cves.png)

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

All graphs and statistics were generated using Python with pandas, matplotlib, and seaborn.

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
    
    # Use NVD as primary, CVE List V5 as secondary
    df = nvd_df if nvd_df is not None else cvelist_df
    full_df = full_nvd_df if full_nvd_df is not None else full_cvelist_df
    
    print(f"\nUsing primary dataset: {len(df):,} active CVEs (excluded rejected)")
    
    # Calculate statistics
    print("\nCalculating statistics...")
    stats = calculate_stats(df, cvelist_df, full_nvd_df, full_cvelist_df)
    
    # Generate all graphs
    print("\nGenerating graphs...")
    yearly_data = graph_cves_by_year(df)
    graph_yoy_growth(yearly_data)
    cumulative_total = graph_cumulative_growth(yearly_data)
    peak_month, peak_count = graph_2025_monthly(df)
    graph_cvss_distribution(df)
    graph_severity_breakdown(df)
    top_cwes = graph_top_cwes(df)
    graph_cvss_by_year(df)
    graph_data_quality(df)
    
    # Rejected CVE analysis (uses full dataset)
    rejected_stats = graph_rejected_cves(full_df) if full_df is not None else None
    
    # CVE List V5 specific graphs
    cna_df = cvelist_df if cvelist_df is not None else df
    top_cnas = graph_top_cnas(cna_df)
    top_vendors = graph_top_vendors(cna_df)
    
    # Generate blog
    print("\nGenerating blog.md...")
    blog_content = generate_blog(stats, top_cwes, top_cnas, top_vendors, 
                                  peak_month, peak_count, cumulative_total, rejected_stats)
    
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
