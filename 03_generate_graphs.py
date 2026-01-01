#!/usr/bin/env python3
"""
Generate Graphs for 2025 CVE Data Review Blog
Creates all visualizations for the annual CVE review

All graphing functions return the Figure object for reuse by other scripts.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import unified styling
from style_config import (
    COLORS, SEVERITY_COLORS, CWE_NAMES,
    FIG_SIZE, FIG_SIZE_TALL, FIG_SIZE_DOUBLE,
    ANNOTATION_SIZE, SAVE_DPI,
    format_thousands, get_thousands_formatter, save_figure
)

# =============================================================================
# DIRECTORIES
# =============================================================================
OUTPUT_DIR = Path("processed")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)


# =============================================================================
# DATA LOADING
# =============================================================================
def load_data():
    """Load processed data, filtering out rejected CVEs"""
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
        cvelist_df = cvelist_df[~cvelist_df['is_rejected']]
        print(f"  Filtered out {rejected:,} rejected CVEs from CVE List V5")
    
    return nvd_df, cvelist_df


def load_data_with_rejected():
    """Load data including rejected CVEs for rejection analysis"""
    nvd_df = None
    cvelist_df = None
    
    if (OUTPUT_DIR / "nvd_cves.parquet").exists():
        nvd_df = pd.read_parquet(OUTPUT_DIR / "nvd_cves.parquet")
    elif (OUTPUT_DIR / "nvd_cves.csv").exists():
        nvd_df = pd.read_csv(OUTPUT_DIR / "nvd_cves.csv", parse_dates=['published', 'modified'])
    
    if (OUTPUT_DIR / "cvelist_v5.parquet").exists():
        cvelist_df = pd.read_parquet(OUTPUT_DIR / "cvelist_v5.parquet")
    elif (OUTPUT_DIR / "cvelist_v5.csv").exists():
        cvelist_df = pd.read_csv(OUTPUT_DIR / "cvelist_v5.csv", parse_dates=['date_reserved', 'date_published'])
    
    return nvd_df, cvelist_df


# =============================================================================
# GRAPH 1: Total CVEs by Year (Historical Growth)
# =============================================================================
def graph_cves_by_year(df, save_path=None):
    """Bar chart showing CVEs by year. Returns (fig, yearly_data)."""
    print("Generating: CVEs by Year...")
    
    yearly = df.groupby('year').size().reset_index(name='count')
    yearly = yearly[(yearly['year'] >= 1999) & (yearly['year'] <= 2025)]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Highlight 2025 with alert color
    bar_colors = [COLORS['alert'] if y == 2025 else COLORS['primary'] 
                  for y in yearly['year']]
    bars = ax.bar(yearly['year'], yearly['count'], color=bar_colors, 
                  edgecolor='white', linewidth=0.5)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('CVEs Published by Year (1999-2025)')
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
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
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig, yearly


# =============================================================================
# GRAPH 2: Year-over-Year Growth Rate
# =============================================================================
def graph_yoy_growth(yearly_data, save_path=None):
    """Bar chart showing year-over-year growth rate. Returns fig."""
    print("Generating: Year-over-Year Growth...")
    
    yearly = yearly_data.copy()
    yearly['yoy_change'] = yearly['count'].pct_change() * 100
    yearly = yearly[yearly['year'] >= 2000]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Primary for positive, secondary for negative
    colors = [COLORS['primary'] if x >= 0 else COLORS['secondary'] for x in yearly['yoy_change']]
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
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 3: Cumulative CVE Growth
# =============================================================================
def graph_cumulative_growth(yearly_data, save_path=None):
    """Line chart showing cumulative CVE count. Returns (fig, cumulative_total)."""
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
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    # Add milestone lines
    milestones = [50000, 100000, 150000, 200000, 250000, 300000]
    for milestone in milestones:
        if yearly['cumulative'].max() >= milestone:
            ax.axhline(y=milestone, color=COLORS['light'], linestyle='--', linewidth=1, alpha=0.7)
            ax.annotate(f'{milestone//1000}K', xy=(yearly['year'].min() + 0.5, milestone), 
                       fontsize=ANNOTATION_SIZE, color=COLORS['secondary'], va='bottom')
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig, yearly['cumulative'].iloc[-1]


# =============================================================================
# GRAPH 4: 2025 Monthly Distribution
# =============================================================================
def graph_2025_monthly(df, save_path=None):
    """Bar chart showing 2025 CVEs by month. Returns (fig, peak_month, peak_count)."""
    print("Generating: 2025 Monthly Distribution...")
    
    df_2025 = df[df['year'] == 2025].copy()
    
    if 'published' in df_2025.columns:
        df_2025['month'] = pd.to_datetime(df_2025['published']).dt.month
    elif 'date_published' in df_2025.columns:
        df_2025['month'] = pd.to_datetime(df_2025['date_published']).dt.month
    else:
        print("  No date column found for monthly analysis")
        return None, None, None
    
    monthly = df_2025.groupby('month').size().reindex(range(1, 13), fill_value=0)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
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
    
    if save_path:
        save_figure(fig, save_path)
    
    peak_idx = monthly.argmax()
    return fig, month_names[peak_idx], monthly.max()


# =============================================================================
# GRAPH 5: CVSS Score Distribution
# =============================================================================
def graph_cvss_distribution(df, save_path=None):
    """Histogram of CVSS scores. Returns fig."""
    print("Generating: CVSS Score Distribution...")
    
    if 'cvss_v3' in df.columns:
        cvss_col = 'cvss_v3'
    elif 'cvss_v4' in df.columns:
        cvss_col = 'cvss_v4'
    else:
        print("  No CVSS column found")
        return None
    
    df_2025 = df[(df['year'] == 2025) & (df[cvss_col].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with CVSS scores")
        return None
    
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
    ax.axvline(x=mean_score, color=COLORS['alert'], linestyle='--', linewidth=2.5)
    ax.axvline(x=median_score, color=COLORS['secondary'], linestyle='--', linewidth=2.5)
    
    # Stats box
    textstr = f'Mean: {mean_score:.2f}\nMedian: {median_score:.2f}\nTotal: {len(df_2025):,}'
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=ANNOTATION_SIZE,
            verticalalignment='top', color=COLORS['text'],
            bbox=dict(boxstyle='round', facecolor='white', edgecolor=COLORS['light'], alpha=0.9))
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 6: Severity Breakdown
# =============================================================================
def graph_severity_breakdown(df, save_path=None):
    """Horizontal bar chart of severity distribution. Returns fig."""
    print("Generating: Severity Breakdown...")
    
    df_2025 = df[(df['year'] == 2025) & (df['severity'].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with severity")
        return None
    
    severity_counts = df_2025['severity'].str.upper().value_counts()
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
    severity_counts = severity_counts.reindex(severity_order).dropna()
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    y_pos = range(len(severity_counts))
    bar_colors = [SEVERITY_COLORS.get(s, COLORS['secondary']) for s in severity_counts.index[::-1]]
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
    
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 7: Top CWEs
# =============================================================================
def graph_top_cwes(df, top_n=15, save_path=None):
    """Horizontal bar chart of most common CWEs. Returns (fig, top_cwes_list)."""
    print("Generating: Top CWEs...")
    
    df_2025 = df[(df['year'] == 2025) & (df['cwe'].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with CWE")
        return None, []
    
    cwe_counts = df_2025['cwe'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(cwe_counts))
    bars = ax.barh(y_pos, cwe_counts.values, color=COLORS['primary'], edgecolor='white')
    
    labels = [f"{cwe} ({CWE_NAMES.get(cwe, '')})" if cwe in CWE_NAMES else cwe 
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
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    top_cwes_list = list(zip(cwe_counts.index[:5], cwe_counts.values[:5]))
    return fig, top_cwes_list


# =============================================================================
# GRAPH 8: Top CNAs (from CVE List V5)
# =============================================================================
def graph_top_cnas(df, top_n=20, save_path=None):
    """Horizontal bar chart of most active CNAs. Returns (fig, top_cnas_list)."""
    print("Generating: Top CNAs...")
    
    if 'assigner_short_name' not in df.columns:
        print("  No CNA data available")
        return None, []
    
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
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    top_cnas_list = list(zip(cna_counts.index[:5], cna_counts.values[:5]))
    return fig, top_cnas_list


# =============================================================================
# GRAPH 9: CVEs with/without CVSS, CWE, CPE
# =============================================================================
def graph_data_quality(df, save_path=None):
    """Grouped bar chart showing data completeness. Returns fig."""
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
           color=COLORS['accent'], edgecolor='white')
    ax.bar(x + width, metrics_df['cpe_pct'], width, label='Has CPE', 
           color=COLORS['secondary'], edgecolor='white')
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Percentage (%)')
    ax.set_title('CVE Data Quality Over Time (CVSS, CWE, CPE Coverage)')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_df['year'].astype(int))
    ax.legend(loc='lower right')
    ax.set_ylim(0, 100)
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 10: Rejected CVEs Over Time
# =============================================================================
def graph_rejected_cves(df, save_path=None):
    """Bar chart showing rejected CVEs by year. Returns (fig, rejected_stats)."""
    print("Generating: Rejected CVEs...")
    
    if 'is_rejected' not in df.columns:
        print("  No rejection data available")
        return None, None
    
    rejected = df[df['is_rejected'] == True].groupby('year').size()
    total = df.groupby('year').size()
    
    rejection_rate = (rejected / total * 100).fillna(0)
    rejected_recent = rejected[rejected.index >= 2015]
    rejection_rate = rejection_rate[rejection_rate.index >= 2015]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIG_SIZE_DOUBLE)
    
    # Bar chart - rejected count
    ax1.bar(rejected_recent.index, rejected_recent.values, color=COLORS['primary'], edgecolor='white')
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Number of Rejected CVEs')
    ax1.set_title('Rejected CVEs by Year')
    ax1.yaxis.set_major_formatter(get_thousands_formatter())
    
    # Line chart - rejection rate
    ax2.plot(rejection_rate.index, rejection_rate.values, marker='o', 
             color=COLORS['primary'], linewidth=2.5, markersize=6)
    ax2.fill_between(rejection_rate.index, rejection_rate.values, 
                     alpha=0.2, color=COLORS['primary'])
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Rejection Rate (%)')
    ax2.set_title('CVE Rejection Rate by Year')
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    rejected_stats = {
        'rejected_2025': rejected_recent.get(2025, 0),
        'rate_2025': rejection_rate.get(2025, 0),
        'total_rejected': rejected.sum()
    }
    
    return fig, rejected_stats


# =============================================================================
# GRAPH 11: Published vs Reserved (CVE V5)
# =============================================================================
def graph_cve_states(df, save_path=None):
    """Bar chart showing CVE states. Returns fig."""
    print("Generating: CVE States...")
    
    if 'state' not in df.columns:
        print("  No state data available")
        return None
    
    df_2025 = df[df['year'] == 2025].copy()
    state_counts = df_2025['state'].value_counts()
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Use primary/secondary/light for states
    state_colors = {
        'PUBLISHED': COLORS['primary'],
        'REJECTED': COLORS['secondary'],
        'RESERVED': COLORS['light']
    }
    bar_colors = [state_colors.get(s, COLORS['accent']) for s in state_counts.index]
    
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
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 12: CVE ID Number Ranges Used
# =============================================================================
def graph_cve_id_ranges(df, save_path=None):
    """Histogram of CVE ID number distribution. Returns fig."""
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
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 13: CVSS Score Comparison by Year
# =============================================================================
def graph_cvss_by_year(df, save_path=None):
    """Box plot comparing CVSS scores across years. Returns fig."""
    print("Generating: CVSS by Year...")
    
    df_recent = df[(df['year'] >= 2018) & (df['cvss_v3'].notna())].copy()
    
    if len(df_recent) == 0:
        print("  No CVSS data available")
        return None
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    years = sorted(df_recent['year'].unique())
    data = [df_recent[df_recent['year'] == y]['cvss_v3'].values for y in years]
    
    bp = ax.boxplot(data, labels=years, patch_artist=True)
    
    # All boxes same primary color
    for i, box in enumerate(bp['boxes']):
        box.set_facecolor(COLORS['primary'])
        box.set_alpha(0.7)
        box.set_edgecolor(COLORS['text'])
    
    # Style whiskers and caps
    for whisker in bp['whiskers']:
        whisker.set_color(COLORS['secondary'])
    for cap in bp['caps']:
        cap.set_color(COLORS['secondary'])
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
            va='center', color=COLORS['secondary'])
    ax.text(len(years) + 0.3, 7.0, 'High', fontsize=ANNOTATION_SIZE - 1, 
            va='center', color=COLORS['secondary'])
    ax.text(len(years) + 0.3, 4.0, 'Medium', fontsize=ANNOTATION_SIZE - 1, 
            va='center', color=COLORS['secondary'])
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 14: Top Vendors (from CVE V5)
# =============================================================================
def graph_top_vendors(df, top_n=20, save_path=None):
    """Horizontal bar chart of vendors with most CVEs. Returns (fig, top_vendors_list)."""
    print("Generating: Top Vendors...")
    
    if 'vendor' not in df.columns:
        print("  No vendor data available")
        return None, []
    
    df_2025 = df[(df['year'] == 2025) & (df['vendor'].notna())].copy()
    df_2025['vendor_clean'] = df_2025['vendor'].str.lower().str.strip()
    
    # Filter out n/a, unknown, none values
    exclude_values = ['n/a', 'unknown', 'none', 'na', 'n_a', '*', '']
    df_2025 = df_2025[~df_2025['vendor_clean'].isin(exclude_values)]
    
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
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    top_vendors_list = list(zip(vendor_counts.index[:5], vendor_counts.values[:5]))
    return fig, top_vendors_list


# =============================================================================
# GRAPH 15: Days to Publish (Reserved to Published)
# =============================================================================
def graph_time_to_publish(df, save_path=None):
    """Histogram of time between reservation and publication. Returns fig."""
    print("Generating: Time to Publish...")
    
    if 'date_reserved' not in df.columns or 'date_published' not in df.columns:
        print("  No date data available")
        return None
    
    df_2025 = df[(df['year'] == 2025) & 
                  (df['date_reserved'].notna()) & 
                  (df['date_published'].notna())].copy()
    
    df_2025['days_to_publish'] = (pd.to_datetime(df_2025['date_published']) - 
                                   pd.to_datetime(df_2025['date_reserved'])).dt.days
    
    df_2025 = df_2025[(df_2025['days_to_publish'] >= 0) & (df_2025['days_to_publish'] <= 365)]
    
    if len(df_2025) == 0:
        print("  No valid time-to-publish data")
        return None
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    ax.hist(df_2025['days_to_publish'], bins=50, color=COLORS['primary'], 
            edgecolor='white', alpha=0.85)
    
    ax.set_xlabel('Days from Reserved to Published')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('Time to Publish CVEs in 2025')
    
    # Statistics lines
    mean_days = df_2025['days_to_publish'].mean()
    median_days = df_2025['days_to_publish'].median()
    ax.axvline(x=mean_days, color=COLORS['alert'], linestyle='--', linewidth=2.5)
    ax.axvline(x=median_days, color=COLORS['secondary'], linestyle='--', linewidth=2.5)
    
    textstr = f'Mean: {mean_days:.1f} days\nMedian: {median_days:.1f} days'
    ax.text(0.98, 0.98, textstr, transform=ax.transAxes, fontsize=ANNOTATION_SIZE,
            verticalalignment='top', horizontalalignment='right', color=COLORS['text'],
            bbox=dict(boxstyle='round', facecolor='white', edgecolor=COLORS['light'], alpha=0.9))
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


# =============================================================================
# GRAPH 16: CVEs by Day of Week (Patch Tuesday Effect)
# =============================================================================
def graph_day_of_week(df, save_path=None):
    """Bar chart showing CVEs by day of week. Returns (fig, day_stats)."""
    print("Generating: CVEs by Day of Week...")
    
    df_2025 = df[df['year'] == 2025].copy()
    
    if 'published' not in df_2025.columns:
        print("  No published date available")
        return None, None
    
    df_2025['published'] = pd.to_datetime(df_2025['published'])
    df_2025['day_of_week'] = df_2025['published'].dt.dayofweek  # 0=Monday, 6=Sunday
    
    day_counts = df_2025.groupby('day_of_week').size()
    day_counts = day_counts.reindex(range(7), fill_value=0)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    
    # Highlight Tuesday (Patch Tuesday effect)
    bar_colors = [COLORS['alert'] if i == 1 else COLORS['primary'] for i in range(7)]
    bars = ax.bar(day_names, day_counts.values, color=bar_colors, edgecolor='white')
    
    ax.set_xlabel('Day of Week')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVEs Published by Day of Week')
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height):,}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=ANNOTATION_SIZE,
                    color=COLORS['text'])
    
    # Add average line - legend on left
    avg = day_counts.mean()
    ax.axhline(y=avg, color=COLORS['secondary'], linestyle='--', linewidth=2,
               label=f'Daily Average: {avg:,.0f}')
    ax.legend(loc='upper left')
    
    # Add "Patch Tuesday" annotation
    ax.annotate('Patch Tuesday', xy=(1, day_counts[1]), xytext=(2.5, day_counts[1] * 1.1),
                arrowprops=dict(arrowstyle='->', color=COLORS['secondary']),
                fontsize=ANNOTATION_SIZE, color=COLORS['secondary'])
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    day_stats = {
        'peak_day': day_names[day_counts.argmax()],
        'peak_count': day_counts.max(),
        'tuesday_count': day_counts[1],
        'weekend_avg': (day_counts[5] + day_counts[6]) / 2,
        'weekday_avg': day_counts[:5].mean()
    }
    
    return fig, day_stats


# =============================================================================
# GRAPH 17: Top 10 Days with Most CVEs
# =============================================================================
def graph_top_days(df, top_n=10, save_path=None):
    """Bar chart showing top N days with most CVEs. Returns (fig, top_days_list)."""
    print("Generating: Top Days with Most CVEs...")
    
    df_2025 = df[df['year'] == 2025].copy()
    
    if 'published' not in df_2025.columns:
        print("  No published date available")
        return None, []
    
    df_2025['published'] = pd.to_datetime(df_2025['published'])
    df_2025['date'] = df_2025['published'].dt.date
    
    daily_counts = df_2025.groupby('date').size().sort_values(ascending=False).head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    # Format dates for display
    date_labels = [d.strftime('%b %d') for d in daily_counts.index]
    x_pos = range(len(daily_counts))
    
    bars = ax.bar(x_pos, daily_counts.values, color=COLORS['primary'], edgecolor='white')
    
    # Highlight the top day
    bars[0].set_color(COLORS['alert'])
    
    ax.set_xlabel('Date')
    ax.set_ylabel('Number of CVEs')
    ax.set_title(f'Top {top_n} Days with Most CVEs in 2025')
    
    ax.set_xticks(x_pos)
    ax.set_xticklabels(date_labels, rotation=45, ha='right')
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height):,}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=ANNOTATION_SIZE,
                    color=COLORS['text'])
    
    # Add day of week info
    for i, (date, count) in enumerate(daily_counts.items()):
        dow = pd.Timestamp(date).strftime('%a')
        ax.annotate(f'({dow})',
                    xy=(i, count * 0.5),
                    ha='center', va='center', fontsize=ANNOTATION_SIZE - 1,
                    color='white', fontweight='bold')
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    top_days_list = [(d.strftime('%Y-%m-%d'), c) for d, c in daily_counts.head(5).items()]
    return fig, top_days_list


# =============================================================================
# GRAPH 18: Top Products (CPE Deep Dive)
# =============================================================================
def graph_top_products(df, top_n=15, save_path=None):
    """Horizontal bar chart of most vulnerable products. Returns (fig, top_products_list)."""
    print("Generating: Top Products...")
    
    if 'product' not in df.columns:
        print("  No product data available")
        return None, []
    
    df_2025 = df[(df['year'] == 2025) & (df['product'].notna())].copy()
    
    if len(df_2025) == 0:
        print("  No 2025 CVEs with product data")
        return None, []
    
    # Clean product names
    df_2025['product_clean'] = df_2025['product'].str.lower().str.strip()
    
    # Filter out n/a, unknown, none values
    exclude_values = ['n/a', 'unknown', 'none', 'na', 'n_a', '*', '']
    df_2025 = df_2025[~df_2025['product_clean'].isin(exclude_values)]
    
    df_2025['product_clean'] = df_2025['product_clean'].str.replace('_', ' ')
    df_2025['product_clean'] = df_2025['product_clean'].str.title()
    
    product_counts = df_2025['product_clean'].value_counts().head(top_n)
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = range(len(product_counts))
    bars = ax.barh(y_pos, product_counts.values, color=COLORS['primary'], edgecolor='white')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(product_counts.index)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title(f'Top {top_n} Most Vulnerable Products in 2025')
    
    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{int(width):,}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    top_products_list = list(zip(product_counts.index[:5], product_counts.values[:5]))
    return fig, top_products_list


# =============================================================================
# SUMMARY STATISTICS
# =============================================================================
def generate_summary_stats(nvd_df, cvelist_df):
    """Generate summary statistics for the blog. Returns stats dict."""
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
# MAIN - Generate all graphs as standalone
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
        
        _, yearly_data = graph_cves_by_year(nvd_df, save_path=GRAPHS_DIR / '01_cves_by_year.png')
        graph_yoy_growth(yearly_data, save_path=GRAPHS_DIR / '02_yoy_growth.png')
        graph_cumulative_growth(yearly_data, save_path=GRAPHS_DIR / '03_cumulative_growth.png')
        graph_2025_monthly(nvd_df, save_path=GRAPHS_DIR / '04_2025_monthly.png')
        graph_cvss_distribution(nvd_df, save_path=GRAPHS_DIR / '05_cvss_distribution.png')
        graph_severity_breakdown(nvd_df, save_path=GRAPHS_DIR / '06_severity_breakdown.png')
        graph_top_cwes(nvd_df, save_path=GRAPHS_DIR / '07_top_cwes.png')
        graph_data_quality(nvd_df, save_path=GRAPHS_DIR / '09_data_quality.png')
        graph_cve_id_ranges(nvd_df, save_path=GRAPHS_DIR / '12_cve_id_ranges.png')
        graph_cvss_by_year(nvd_df, save_path=GRAPHS_DIR / '13_cvss_by_year.png')
        
        # New deep dive graphs
        graph_day_of_week(nvd_df, save_path=GRAPHS_DIR / '16_day_of_week.png')
        graph_top_days(nvd_df, save_path=GRAPHS_DIR / '17_top_days.png')
        graph_top_products(nvd_df, save_path=GRAPHS_DIR / '18_top_products.png')
        
        # Rejected CVE analysis (needs full data)
        full_nvd, _ = load_data_with_rejected()
        if full_nvd is not None:
            graph_rejected_cves(full_nvd, save_path=GRAPHS_DIR / '10_rejected_cves.png')
    
    # Generate graphs from CVE List V5 data
    if cvelist_df is not None:
        print(f"\nCVE List V5 Data: {len(cvelist_df):,} CVEs")
        
        graph_top_cnas(cvelist_df, save_path=GRAPHS_DIR / '08_top_cnas.png')
        graph_cve_states(cvelist_df, save_path=GRAPHS_DIR / '11_cve_states.png')
        graph_top_vendors(cvelist_df, save_path=GRAPHS_DIR / '14_top_vendors.png')
        graph_time_to_publish(cvelist_df, save_path=GRAPHS_DIR / '15_time_to_publish.png')
    
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
