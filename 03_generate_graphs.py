#!/usr/bin/env python3
"""
Generate Graphs for 2025 CVE Data Review Blog
Creates all visualizations for the annual CVE review
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# =============================================================================
# PROFESSIONAL STYLING CONFIGURATION
# =============================================================================

# Standard figure sizes (all graphs use same dimensions)
FIG_SIZE = (12, 6)           # Standard for all single charts
FIG_SIZE_TALL = (12, 8)      # For horizontal bar charts with many items
FIG_SIZE_DOUBLE = (14, 6)    # For side-by-side charts

# Professional blue/grey color palette
COLORS = {
    'primary': '#1e3a5f',      # Dark navy blue - main bars/lines
    'secondary': '#3d6a99',    # Medium blue - secondary elements
    'accent': '#5a9bd4',       # Light blue - highlights
    'highlight': '#2563eb',    # Bright blue - current year highlight
    'neutral': '#64748b',      # Slate grey - neutral elements
    'light': '#94a3b8',        # Light grey - background elements
    'text': '#1e293b',         # Dark slate - text
    'grid': '#e2e8f0',         # Very light grey - gridlines
}

# Severity colors (kept distinct for clarity but muted)
SEVERITY_COLORS = {
    'CRITICAL': '#7f1d1d',     # Dark red
    'HIGH': '#b91c1c',         # Red
    'MEDIUM': '#d97706',       # Amber
    'LOW': '#059669',          # Green
    'NONE': '#64748b'          # Grey
}

# Typography
TITLE_SIZE = 16
LABEL_SIZE = 12
TICK_SIZE = 10
ANNOTATION_SIZE = 9

# Output settings
SAVE_DPI = 300

# Apply global matplotlib settings
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': TICK_SIZE,
    'axes.titlesize': TITLE_SIZE,
    'axes.titleweight': 'bold',
    'axes.labelsize': LABEL_SIZE,
    'axes.labelweight': 'bold',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'axes.facecolor': 'white',
    'axes.edgecolor': COLORS['neutral'],
    'axes.grid': True,
    'grid.color': COLORS['grid'],
    'grid.linewidth': 0.5,
    'grid.alpha': 0.7,
    'xtick.labelsize': TICK_SIZE,
    'ytick.labelsize': TICK_SIZE,
    'legend.fontsize': TICK_SIZE,
    'figure.facecolor': 'white',
    'figure.edgecolor': 'white',
    'savefig.facecolor': 'white',
    'savefig.edgecolor': 'white',
})

# Directories
OUTPUT_DIR = Path("processed")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)

def load_data():
    """Load processed data"""
    print("Loading processed data...")
    
    nvd_df = None
    cvelist_df = None
    
    # Try parquet first, then CSV
    if (OUTPUT_DIR / "nvd_cves.parquet").exists():
        nvd_df = pd.read_parquet(OUTPUT_DIR / "nvd_cves.parquet")
    elif (OUTPUT_DIR / "nvd_cves.csv").exists():
        nvd_df = pd.read_csv(OUTPUT_DIR / "nvd_cves.csv", parse_dates=['published', 'modified'])
    
    if (OUTPUT_DIR / "cvelist_v5.parquet").exists():
        cvelist_df = pd.read_parquet(OUTPUT_DIR / "cvelist_v5.parquet")
    elif (OUTPUT_DIR / "cvelist_v5.csv").exists():
        cvelist_df = pd.read_csv(OUTPUT_DIR / "cvelist_v5.csv", parse_dates=['date_reserved', 'date_published'])
    
    # Filter out rejected CVEs for main analysis
    if nvd_df is not None and 'is_rejected' in nvd_df.columns:
        rejected = nvd_df['is_rejected'].sum()
        nvd_df = nvd_df[~nvd_df['is_rejected']]
        print(f"  Filtered out {rejected:,} rejected CVEs from NVD")
    
    if cvelist_df is not None and 'is_rejected' in cvelist_df.columns:
        rejected = cvelist_df['is_rejected'].sum()
        cvelist_df_full = cvelist_df.copy()  # Keep full for rejected analysis
        cvelist_df = cvelist_df[~cvelist_df['is_rejected']]
        print(f"  Filtered out {rejected:,} rejected CVEs from CVE List V5")
    
    return nvd_df, cvelist_df

def format_thousands(x, pos):
    """Format axis labels with K suffix"""
    if x >= 1000:
        return f'{int(x/1000)}K'
    return f'{int(x)}'

def save_figure(fig, filename):
    """Save figure with consistent settings"""
    fig.savefig(GRAPHS_DIR / filename, dpi=SAVE_DPI, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)

# =============================================================================
# GRAPH 1: Total CVEs by Year (Historical Growth)
# =============================================================================
def graph_cves_by_year(df, source='NVD'):
    """Bar chart showing CVEs by year"""
    print("Generating: CVEs by Year...")
    
    yearly = df.groupby('year').size().reset_index(name='count')
    yearly = yearly[(yearly['year'] >= 1999) & (yearly['year'] <= 2025)]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Create bars with consistent color, highlight 2025
    bar_colors = [COLORS['highlight'] if y == 2025 else COLORS['primary'] 
                  for y in yearly['year']]
    bars = ax.bar(yearly['year'], yearly['count'], color=bar_colors, 
                  edgecolor='white', linewidth=0.5)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('CVEs Published by Year (1999-2025)')
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    ax.set_xticks(yearly['year'])
    ax.set_xticklabels(yearly['year'], rotation=45, ha='right')
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height):,}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=7, rotation=90,
                    color=COLORS['text'])
    
    plt.tight_layout()
    save_figure(fig, '01_cves_by_year.png')
    
    return yearly

# =============================================================================
# GRAPH 2: Year-over-Year Growth Rate
# =============================================================================
def graph_yoy_growth(yearly_data):
    """Bar chart showing year-over-year growth rate"""
    print("Generating: Year-over-Year Growth...")
    
    yearly = yearly_data.copy()
    yearly['yoy_change'] = yearly['count'].pct_change() * 100
    yearly = yearly[yearly['year'] >= 2000]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Blue for positive, grey for negative
    colors = [COLORS['primary'] if x >= 0 else COLORS['neutral'] for x in yearly['yoy_change']]
    ax.bar(yearly['year'], yearly['yoy_change'], color=colors, 
           edgecolor='white', linewidth=0.5)
    ax.axhline(y=0, color=COLORS['text'], linestyle='-', linewidth=1)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Year-over-Year Change (%)')
    ax.set_title('CVE Year-over-Year Growth Rate (2000-2025)')
    
    ax.set_xticks(yearly['year'])
    ax.set_xticklabels(yearly['year'].astype(int), rotation=45, ha='right')
    
    # Add value labels
    for year, val in zip(yearly['year'], yearly['yoy_change']):
        if pd.notna(val):
            ax.annotate(f'{val:.0f}%',
                        xy=(year, val),
                        xytext=(0, 5 if val >= 0 else -12),
                        textcoords="offset points",
                        ha='center', va='bottom' if val >= 0 else 'top', 
                        fontsize=ANNOTATION_SIZE - 1, color=COLORS['text'])
    
    plt.tight_layout()
    save_figure(fig, '02_yoy_growth.png')

# =============================================================================
# GRAPH 3: Cumulative CVE Growth
# =============================================================================
def graph_cumulative_growth(yearly_data):
    """Line chart showing cumulative CVE count"""
    print("Generating: Cumulative Growth...")
    
    yearly = yearly_data.copy()
    yearly['cumulative'] = yearly['count'].cumsum()
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    ax.fill_between(yearly['year'], yearly['cumulative'], alpha=0.2, color=COLORS['primary'])
    ax.plot(yearly['year'], yearly['cumulative'], color=COLORS['primary'], 
            linewidth=2.5, marker='o', markersize=4)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Cumulative CVEs')
    ax.set_title('Cumulative CVE Count Over Time')
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    # Add milestone lines
    milestones = [50000, 100000, 150000, 200000, 250000, 300000]
    for milestone in milestones:
        if yearly['cumulative'].max() >= milestone:
            ax.axhline(y=milestone, color=COLORS['light'], linestyle='--', linewidth=1, alpha=0.7)
            ax.annotate(f'{milestone//1000}K', xy=(yearly['year'].min() + 0.5, milestone), 
                       fontsize=ANNOTATION_SIZE, color=COLORS['neutral'], va='bottom')
    
    plt.tight_layout()
    save_figure(fig, '03_cumulative_growth.png')

# =============================================================================
# GRAPH 4: 2025 Monthly Distribution
# =============================================================================
def graph_2025_monthly(df):
    """Bar chart showing 2025 CVEs by month"""
    print("Generating: 2025 Monthly Distribution...")
    
    df_2025 = df[df['year'] == 2025].copy()
    
    if 'published' in df_2025.columns:
        df_2025['month'] = pd.to_datetime(df_2025['published']).dt.month
    elif 'date_published' in df_2025.columns:
        df_2025['month'] = pd.to_datetime(df_2025['date_published']).dt.month
    else:
        print("  No date column found for monthly analysis")
        return
    
    monthly = df_2025.groupby('month').size().reindex(range(1, 13), fill_value=0)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    # All bars same color for consistency
    bars = ax.bar(month_names, monthly.values, color=COLORS['primary'], edgecolor='white')
    
    ax.set_xlabel('Month')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVEs by Month')
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(f'{int(height):,}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=ANNOTATION_SIZE,
                        color=COLORS['text'])
    
    # Add average line - legend on left side
    avg = monthly.mean()
    ax.axhline(y=avg, color=COLORS['secondary'], linestyle='--', linewidth=2, 
               label=f'Monthly Average: {avg:,.0f}')
    ax.legend(loc='upper left')
    
    plt.tight_layout()
    save_figure(fig, '04_2025_monthly.png')

# =============================================================================
# GRAPH 5: CVSS Score Distribution
# =============================================================================
def graph_cvss_distribution(df):
    """Histogram of CVSS scores - professional blue/grey styling"""
    print("Generating: CVSS Score Distribution...")
    
    if 'cvss_v3' in df.columns:
        cvss_col = 'cvss_v3'
    elif 'cvss_v4' in df.columns:
        cvss_col = 'cvss_v4'
    else:
        print("  No CVSS column found")
        return
    
    df_2025 = df[(df['year'] == 2025) & (df[cvss_col].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with CVSS scores")
        return
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    bins = np.arange(0, 10.5, 0.5)
    ax.hist(df_2025[cvss_col], bins=bins, color=COLORS['primary'], 
            edgecolor='white', linewidth=0.5, alpha=0.85)
    
    ax.set_xlabel('CVSS Score')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVE CVSS Score Distribution')
    
    # Add statistics lines
    mean_score = df_2025[cvss_col].mean()
    median_score = df_2025[cvss_col].median()
    ax.axvline(x=mean_score, color=COLORS['highlight'], linestyle='--', linewidth=2.5)
    ax.axvline(x=median_score, color=COLORS['secondary'], linestyle='--', linewidth=2.5)
    
    # Stats box
    textstr = f'Mean: {mean_score:.2f}\nMedian: {median_score:.2f}\nTotal: {len(df_2025):,}'
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=ANNOTATION_SIZE,
            verticalalignment='top', color=COLORS['text'],
            bbox=dict(boxstyle='round', facecolor='white', edgecolor=COLORS['light'], alpha=0.9))
    
    plt.tight_layout()
    save_figure(fig, '05_cvss_distribution.png')

# =============================================================================
# GRAPH 6: Severity Breakdown
# =============================================================================
def graph_severity_breakdown(df):
    """Horizontal bar chart of severity distribution - blue gradient"""
    print("Generating: Severity Breakdown...")
    
    df_2025 = df[(df['year'] == 2025) & (df['severity'].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with severity")
        return
    
    severity_counts = df_2025['severity'].str.upper().value_counts()
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
    severity_counts = severity_counts.reindex(severity_order).dropna()
    
    # Professional blue gradient for severity
    sev_colors = {
        'CRITICAL': '#0c2340',  # Darkest navy
        'HIGH': '#1e3a5f',      # Dark navy
        'MEDIUM': '#3d6a99',    # Medium blue
        'LOW': '#6b9dc9',       # Light blue
        'NONE': '#a8c5db'       # Lightest blue
    }
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    y_pos = range(len(severity_counts))
    bar_colors = [sev_colors.get(s, COLORS['neutral']) for s in severity_counts.index[::-1]]
    bars = ax.barh(y_pos, severity_counts.values[::-1], color=bar_colors, edgecolor='white')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(severity_counts.index[::-1])
    ax.set_xlabel('Number of CVEs')
    ax.set_title('2025 CVEs by Severity')
    
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '06_severity_breakdown.png')

# =============================================================================
# GRAPH 7: Top CWEs
# =============================================================================
def graph_top_cwes(df, top_n=15):
    """Horizontal bar chart of most common CWEs"""
    print("Generating: Top CWEs...")
    
    df_2025 = df[(df['year'] == 2025) & (df['cwe'].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with CWE")
        return
    
    cwe_counts = df_2025['cwe'].value_counts().head(top_n)
    
    cwe_names = {
        'CWE-79': 'XSS', 'CWE-89': 'SQL Injection', 'CWE-787': 'OOB Write',
        'CWE-125': 'OOB Read', 'CWE-20': 'Input Validation', 'CWE-22': 'Path Traversal',
        'CWE-352': 'CSRF', 'CWE-78': 'Command Injection', 'CWE-416': 'Use After Free',
        'CWE-190': 'Integer Overflow', 'CWE-476': 'NULL Pointer', 'CWE-119': 'Buffer Overflow',
        'CWE-200': 'Info Exposure', 'CWE-400': 'Resource Exhaustion', 'CWE-434': 'File Upload',
        'CWE-863': 'Auth Bypass', 'CWE-918': 'SSRF', 'CWE-94': 'Code Injection',
        'CWE-502': 'Deserialization', 'CWE-287': 'Auth Issues',
        'NVD-CWE-noinfo': 'No Info', 'NVD-CWE-Other': 'Other'
    }
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(cwe_counts))
    bars = ax.barh(y_pos, cwe_counts.values, color=COLORS['primary'], edgecolor='white')
    
    labels = [f"{cwe} ({cwe_names.get(cwe, '')})" if cwe in cwe_names else cwe 
              for cwe in cwe_counts.index]
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title(f'Top {top_n} CWEs in 2025')
    
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '07_top_cwes.png')

# =============================================================================
# GRAPH 8: Top CNAs (from CVE List V5)
# =============================================================================
def graph_top_cnas(df, top_n=20):
    """Horizontal bar chart of most active CNAs"""
    print("Generating: Top CNAs...")
    
    if 'assigner_short_name' not in df.columns:
        print("  No CNA data available")
        return
    
    df_2025 = df[df['year'] == 2025].copy()
    cna_counts = df_2025['assigner_short_name'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(cna_counts))
    bars = ax.barh(y_pos, cna_counts.values, color=COLORS['primary'], edgecolor='white')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(cna_counts.index)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title(f'Top {top_n} CVE Numbering Authorities (CNAs) in 2025')
    
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '08_top_cnas.png')

# =============================================================================
# GRAPH 9: CVEs with/without CVSS, CWE, CPE
# =============================================================================
def graph_data_quality(df):
    """Grouped bar chart showing data completeness - blue/grey gradient"""
    print("Generating: Data Quality Metrics...")
    
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
            'year': year, 'total': total,
            'cvss_pct': (has_cvss / total) * 100,
            'cwe_pct': (has_cwe / total) * 100,
            'cpe_pct': (has_cpe / total) * 100
        })
    
    metrics_df = pd.DataFrame(metrics)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    x = np.arange(len(metrics_df))
    width = 0.25
    
    ax.bar(x - width, metrics_df['cvss_pct'], width, label='Has CVSS', 
           color=COLORS['primary'], edgecolor='white')
    ax.bar(x, metrics_df['cwe_pct'], width, label='Has CWE', 
           color=COLORS['secondary'], edgecolor='white')
    ax.bar(x + width, metrics_df['cpe_pct'], width, label='Has CPE', 
           color=COLORS['neutral'], edgecolor='white')
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Percentage (%)')
    ax.set_title('CVE Data Quality Over Time (CVSS, CWE, CPE Coverage)')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_df['year'].astype(int))
    ax.legend(loc='lower right')
    ax.set_ylim(0, 100)
    
    plt.tight_layout()
    save_figure(fig, '09_data_quality.png')

# =============================================================================
# GRAPH 10: Rejected CVEs Over Time
# =============================================================================
def graph_rejected_cves(df):
    """Bar chart showing rejected CVEs by year - using neutral grey"""
    print("Generating: Rejected CVEs...")
    
    if 'is_rejected' not in df.columns:
        print("  No rejection data available")
        return
    
    rejected = df[df['is_rejected'] == True].groupby('year').size()
    total = df.groupby('year').size()
    
    rejection_rate = (rejected / total * 100).fillna(0)
    rejected_recent = rejected[rejected.index >= 2015]
    rejection_rate = rejection_rate[rejection_rate.index >= 2015]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Bar chart - rejected count (same primary color)
    ax1.bar(rejected_recent.index, rejected_recent.values, color=COLORS['primary'], edgecolor='white')
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Number of Rejected CVEs')
    ax1.set_title('Rejected CVEs by Year')
    ax1.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    # Line chart - rejection rate (same primary color)
    ax2.plot(rejection_rate.index, rejection_rate.values, marker='o', 
             color=COLORS['primary'], linewidth=2.5, markersize=6)
    ax2.fill_between(rejection_rate.index, rejection_rate.values, 
                     alpha=0.2, color=COLORS['primary'])
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Rejection Rate (%)')
    ax2.set_title('CVE Rejection Rate by Year')
    
    plt.tight_layout()
    save_figure(fig, '10_rejected_cves.png')

# =============================================================================
# GRAPH 11: Published vs Reserved (CVE V5)
# =============================================================================
def graph_cve_states(df):
    """Bar chart showing CVE states - blue gradient"""
    print("Generating: CVE States...")
    
    if 'state' not in df.columns:
        print("  No state data available")
        return
    
    df_2025 = df[df['year'] == 2025].copy()
    state_counts = df_2025['state'].value_counts()
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Blue gradient for states
    state_colors = {
        'PUBLISHED': COLORS['primary'],
        'REJECTED': COLORS['neutral'],
        'RESERVED': COLORS['light']
    }
    bar_colors = [state_colors.get(s, COLORS['secondary']) for s in state_counts.index]
    
    bars = ax.bar(state_counts.index, state_counts.values, color=bar_colors, edgecolor='white')
    
    ax.set_xlabel('State')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVE States (from CVE List V5)')
    
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height):,}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=ANNOTATION_SIZE + 1,
                    color=COLORS['text'])
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '11_cve_states.png')

# =============================================================================
# GRAPH 12: CVE ID Number Ranges Used
# =============================================================================
def graph_cve_id_ranges(df):
    """Histogram of CVE ID number distribution"""
    print("Generating: CVE ID Ranges...")
    
    df_2025 = df[df['year'] == 2025].copy()
    df_2025['cve_num'] = df_2025['cve_id'].str.extract(r'CVE-2025-(\d+)')[0].astype(float)
    df_2025 = df_2025[df_2025['cve_num'].notna()]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    ax.hist(df_2025['cve_num'], bins=50, color=COLORS['primary'], 
            edgecolor='white', alpha=0.85)
    
    ax.set_xlabel('CVE ID Number (CVE-2025-XXXXX)')
    ax.set_ylabel('Count')
    ax.set_title('Distribution of 2025 CVE ID Numbers')
    
    # Add statistics
    max_num = df_2025['cve_num'].max()
    textstr = f'Max ID: CVE-2025-{int(max_num)}\nTotal: {len(df_2025):,}'
    ax.text(0.98, 0.98, textstr, transform=ax.transAxes, fontsize=ANNOTATION_SIZE,
            verticalalignment='top', horizontalalignment='right', color=COLORS['text'],
            bbox=dict(boxstyle='round', facecolor='white', edgecolor=COLORS['light'], alpha=0.9))
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '12_cve_id_ranges.png')

# =============================================================================
# GRAPH 13: CVSS Score Comparison by Year
# =============================================================================
def graph_cvss_by_year(df):
    """Box plot comparing CVSS scores across years - blue gradient"""
    print("Generating: CVSS by Year...")
    
    df_recent = df[(df['year'] >= 2018) & (df['cvss_v3'].notna())].copy()
    
    if len(df_recent) == 0:
        print("  No CVSS data available")
        return
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    years = sorted(df_recent['year'].unique())
    data = [df_recent[df_recent['year'] == y]['cvss_v3'].values for y in years]
    
    bp = ax.boxplot(data, labels=years, patch_artist=True)
    
    # All boxes same primary color for consistency
    for i, box in enumerate(bp['boxes']):
        box.set_facecolor(COLORS['primary'])
        box.set_alpha(0.7)
        box.set_edgecolor(COLORS['text'])
    
    # Style whiskers and caps
    for whisker in bp['whiskers']:
        whisker.set_color(COLORS['neutral'])
    for cap in bp['caps']:
        cap.set_color(COLORS['neutral'])
    for median in bp['medians']:
        median.set_color('white')
        median.set_linewidth(2)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('CVSS v3 Score')
    ax.set_title('CVSS Score Distribution by Year')
    
    # Add reference lines (subtle grey)
    ax.axhline(y=9.0, color=COLORS['light'], linestyle='--', alpha=0.6)
    ax.axhline(y=7.0, color=COLORS['light'], linestyle='--', alpha=0.6)
    ax.axhline(y=4.0, color=COLORS['light'], linestyle='--', alpha=0.6)
    
    # Reference labels
    ax.text(len(years) + 0.3, 9.0, 'Critical', fontsize=ANNOTATION_SIZE - 1, 
            va='center', color=COLORS['neutral'])
    ax.text(len(years) + 0.3, 7.0, 'High', fontsize=ANNOTATION_SIZE - 1, 
            va='center', color=COLORS['neutral'])
    ax.text(len(years) + 0.3, 4.0, 'Medium', fontsize=ANNOTATION_SIZE - 1, 
            va='center', color=COLORS['neutral'])
    
    plt.tight_layout()
    save_figure(fig, '13_cvss_by_year.png')

# =============================================================================
# GRAPH 14: Top Vendors (from CVE V5)
# =============================================================================
def graph_top_vendors(df, top_n=20):
    """Horizontal bar chart of vendors with most CVEs"""
    print("Generating: Top Vendors...")
    
    if 'vendor' not in df.columns:
        print("  No vendor data available")
        return
    
    df_2025 = df[(df['year'] == 2025) & (df['vendor'].notna())].copy()
    df_2025['vendor_clean'] = df_2025['vendor'].str.lower().str.strip()
    vendor_counts = df_2025['vendor_clean'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(vendor_counts))
    bars = ax.barh(y_pos, vendor_counts.values, color=COLORS['primary'], edgecolor='white')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(vendor_counts.index)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title(f'Top {top_n} Vendors by CVE Count in 2025')
    
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '14_top_vendors.png')

# =============================================================================
# GRAPH 15: Days to Publish (Reserved to Published)
# =============================================================================
def graph_time_to_publish(df):
    """Histogram of time between reservation and publication"""
    print("Generating: Time to Publish...")
    
    if 'date_reserved' not in df.columns or 'date_published' not in df.columns:
        print("  No date data available")
        return
    
    df_2025 = df[(df['year'] == 2025) & 
                  (df['date_reserved'].notna()) & 
                  (df['date_published'].notna())].copy()
    
    df_2025['days_to_publish'] = (pd.to_datetime(df_2025['date_published']) - 
                                   pd.to_datetime(df_2025['date_reserved'])).dt.days
    
    df_2025 = df_2025[(df_2025['days_to_publish'] >= 0) & (df_2025['days_to_publish'] <= 365)]
    
    if len(df_2025) == 0:
        print("  No valid time-to-publish data")
        return
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    ax.hist(df_2025['days_to_publish'], bins=50, color=COLORS['primary'], 
            edgecolor='white', alpha=0.85)
    
    ax.set_xlabel('Days from Reserved to Published')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('Time to Publish CVEs in 2025')
    
    # Statistics lines
    mean_days = df_2025['days_to_publish'].mean()
    median_days = df_2025['days_to_publish'].median()
    ax.axvline(x=mean_days, color=COLORS['highlight'], linestyle='--', linewidth=2.5)
    ax.axvline(x=median_days, color=COLORS['secondary'], linestyle='--', linewidth=2.5)
    
    textstr = f'Mean: {mean_days:.1f} days\nMedian: {median_days:.1f} days'
    ax.text(0.98, 0.98, textstr, transform=ax.transAxes, fontsize=ANNOTATION_SIZE,
            verticalalignment='top', horizontalalignment='right', color=COLORS['text'],
            bbox=dict(boxstyle='round', facecolor='white', edgecolor=COLORS['light'], alpha=0.9))
    
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(format_thousands))
    
    plt.tight_layout()
    save_figure(fig, '15_time_to_publish.png')

# =============================================================================
# SUMMARY STATISTICS
# =============================================================================
def generate_summary_stats(nvd_df, cvelist_df):
    """Generate summary statistics for the blog"""
    print("\nGenerating summary statistics...")
    
    stats = {}
    
    if nvd_df is not None:
        nvd_2025 = nvd_df[nvd_df['year'] == 2025]
        nvd_2024 = nvd_df[nvd_df['year'] == 2024]
        
        stats['nvd'] = {
            'total_all_time': len(nvd_df),
            'total_2025': len(nvd_2025),
            'total_2024': len(nvd_2024),
            'yoy_change': ((len(nvd_2025) - len(nvd_2024)) / len(nvd_2024) * 100) if len(nvd_2024) > 0 else 0,
            'cvss_v3_coverage_2025': (nvd_2025['cvss_v3'].notna().sum() / len(nvd_2025) * 100) if len(nvd_2025) > 0 else 0,
            'cwe_coverage_2025': (nvd_2025['cwe'].notna().sum() / len(nvd_2025) * 100) if len(nvd_2025) > 0 else 0,
            'avg_cvss_2025': nvd_2025['cvss_v3'].mean() if len(nvd_2025) > 0 else 0,
            'critical_2025': len(nvd_2025[nvd_2025['severity'].str.upper() == 'CRITICAL']) if 'severity' in nvd_2025.columns else 0,
            'high_2025': len(nvd_2025[nvd_2025['severity'].str.upper() == 'HIGH']) if 'severity' in nvd_2025.columns else 0,
        }
    
    if cvelist_df is not None:
        cv_2025 = cvelist_df[cvelist_df['year'] == 2025]
        
        stats['cvelist'] = {
            'total_all_time': len(cvelist_df),
            'total_2025': len(cv_2025),
            'published_2025': cv_2025['is_published'].sum() if 'is_published' in cv_2025.columns else 0,
            'rejected_2025': cv_2025['is_rejected'].sum() if 'is_rejected' in cv_2025.columns else 0,
            'unique_cnas_2025': cv_2025['assigner_short_name'].nunique() if 'assigner_short_name' in cv_2025.columns else 0,
            'unique_vendors_2025': cv_2025['vendor'].nunique() if 'vendor' in cv_2025.columns else 0,
            'top_cna': cv_2025['assigner_short_name'].value_counts().index[0] if 'assigner_short_name' in cv_2025.columns and len(cv_2025) > 0 else 'N/A',
        }
    
    # Save stats to JSON
    import json
    with open(GRAPHS_DIR / 'summary_stats.json', 'w') as f:
        json.dump(stats, f, indent=2, default=str)
    
    # Print summary
    print("\n" + "="*60)
    print("2025 CVE REVIEW SUMMARY STATISTICS")
    print("="*60)
    
    if 'nvd' in stats:
        print(f"\nNVD Data:")
        print(f"  Total CVEs (all time): {stats['nvd']['total_all_time']:,}")
        print(f"  2025 CVEs: {stats['nvd']['total_2025']:,}")
        print(f"  2024 CVEs: {stats['nvd']['total_2024']:,}")
        print(f"  Year-over-Year Change: {stats['nvd']['yoy_change']:+.1f}%")
        print(f"  CVSS Coverage (2025): {stats['nvd']['cvss_v3_coverage_2025']:.1f}%")
        print(f"  CWE Coverage (2025): {stats['nvd']['cwe_coverage_2025']:.1f}%")
        print(f"  Average CVSS (2025): {stats['nvd']['avg_cvss_2025']:.2f}")
        print(f"  Critical Severity (2025): {stats['nvd']['critical_2025']:,}")
        print(f"  High Severity (2025): {stats['nvd']['high_2025']:,}")
    
    if 'cvelist' in stats:
        print(f"\nCVE List V5 Data:")
        print(f"  Total CVEs (all time): {stats['cvelist']['total_all_time']:,}")
        print(f"  2025 CVEs: {stats['cvelist']['total_2025']:,}")
        print(f"  Published (2025): {stats['cvelist']['published_2025']:,}")
        print(f"  Rejected (2025): {stats['cvelist']['rejected_2025']:,}")
        print(f"  Unique CNAs (2025): {stats['cvelist']['unique_cnas_2025']:,}")
        print(f"  Unique Vendors (2025): {stats['cvelist']['unique_vendors_2025']:,}")
        print(f"  Top CNA: {stats['cvelist']['top_cna']}")
    
    return stats

# =============================================================================
# MAIN
# =============================================================================
def main():
    print("="*60)
    print("2025 CVE Data Review - Graph Generation")
    print("="*60)
    
    # Load data
    nvd_df, cvelist_df = load_data()
    
    if nvd_df is None and cvelist_df is None:
        print("ERROR: No data found. Run 02_process_data.py first.")
        return
    
    # Generate graphs from NVD data
    if nvd_df is not None:
        print(f"\nNVD Data: {len(nvd_df):,} CVEs")
        
        yearly_data = graph_cves_by_year(nvd_df, source='NVD')
        graph_yoy_growth(yearly_data)
        graph_cumulative_growth(yearly_data)
        graph_2025_monthly(nvd_df)
        graph_cvss_distribution(nvd_df)
        graph_severity_breakdown(nvd_df)
        graph_top_cwes(nvd_df)
        graph_data_quality(nvd_df)
        graph_rejected_cves(nvd_df)
        graph_cve_id_ranges(nvd_df)
        graph_cvss_by_year(nvd_df)
    
    # Generate graphs from CVE List V5 data
    if cvelist_df is not None:
        print(f"\nCVE List V5 Data: {len(cvelist_df):,} CVEs")
        
        if nvd_df is None:
            yearly_data = graph_cves_by_year(cvelist_df, source='CVE List V5')
            graph_yoy_growth(yearly_data)
            graph_cumulative_growth(yearly_data)
            graph_2025_monthly(cvelist_df)
        
        graph_top_cnas(cvelist_df)
        graph_cve_states(cvelist_df)
        graph_top_vendors(cvelist_df)
        graph_time_to_publish(cvelist_df)
    
    # Generate summary statistics
    stats = generate_summary_stats(nvd_df, cvelist_df)
    
    print("\n" + "="*60)
    print(f"Graphs saved to: {GRAPHS_DIR.absolute()}")
    print("="*60)
    
    # List generated graphs
    print("\nGenerated graphs:")
    for f in sorted(GRAPHS_DIR.glob("*.png")):
        print(f"  - {f.name}")

if __name__ == "__main__":
    main()
