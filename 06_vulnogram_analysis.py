#!/usr/bin/env python3
"""
Vulnogram Generator Analysis for 2025 CVEs
Analyzes which CVEs PUBLISHED in 2025 were created using Vulnogram vs other methods.

This script scans ALL CVE JSON files across all years and filters to those
published in 2025, then categorizes them by whether they contain the 
x_generator field with "Vulnogram" engine.
"""

import json
import os
from pathlib import Path
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
from datetime import datetime
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

# Import unified styling
from style_config import (
    COLORS, FIG_SIZE, FIG_SIZE_TALL,
    ANNOTATION_SIZE, SAVE_DPI, save_figure
)

# =============================================================================
# DIRECTORIES
# =============================================================================
CVE_DATA_DIR = Path("data/cvelistV5/cves")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)


def scan_2025_cves():
    """
    Scan ALL CVE JSON files and filter to those PUBLISHED in 2025.
    Categorizes by x_generator usage.
    
    Returns:
        dict: Statistics about Vulnogram usage for CVEs published in 2025
    """
    print("Scanning ALL CVE files for those published in 2025...")
    print("(This may take a few minutes...)")
    
    stats = {
        'total': 0,
        'with_vulnogram': 0,
        'with_other_generator': 0,
        'no_generator': 0,
        'vulnogram_versions': Counter(),
        'other_generators': Counter(),
        'by_cna': defaultdict(lambda: {'vulnogram': 0, 'other_generator': 0, 'no_generator': 0}),
        'by_month': defaultdict(lambda: {'vulnogram': 0, 'other_generator': 0, 'no_generator': 0}),
        'rejected': 0,
        'skipped_no_date': 0,
        'skipped_other_year': 0,
    }
    
    # Collect all JSON files first
    all_json_files = []
    for year_dir in sorted(CVE_DATA_DIR.iterdir()):
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue
        for subdir in year_dir.iterdir():
            if not subdir.is_dir():
                continue
            all_json_files.extend(subdir.glob("CVE-*.json"))
    
    print(f"Found {len(all_json_files):,} total CVE files to scan...")
    
    # Process all files with progress bar
    for json_file in tqdm(all_json_files, desc="Processing CVEs"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            # Check if rejected
            state = cve_data.get('cveMetadata', {}).get('state', '')
            
            # Get publish date - MUST be published in 2025
            date_published = cve_data.get('cveMetadata', {}).get('datePublished', '')
            
            if not date_published:
                if state == 'REJECTED':
                    # Don't count rejected CVEs without dates
                    pass
                else:
                    stats['skipped_no_date'] += 1
                continue
            
            # Parse the year from published date
            try:
                pub_year = int(date_published[:4])
            except (ValueError, IndexError):
                stats['skipped_no_date'] += 1
                continue
            
            # Only process CVEs published in 2025
            if pub_year != 2025:
                stats['skipped_other_year'] += 1
                continue
            
            # Count rejected CVEs published in 2025
            if state == 'REJECTED':
                stats['rejected'] += 1
                continue
            
            stats['total'] += 1
            
            # Get CNA info
            cna = cve_data.get('cveMetadata', {}).get('assignerShortName', 'Unknown')
            
            # Get month for monthly analysis
            try:
                month = int(date_published[5:7])
            except (ValueError, IndexError):
                month = None
            
            # Check for x_generator in the CNA container
            cna_container = cve_data.get('containers', {}).get('cna', {})
            x_generator = cna_container.get('x_generator', {})
            
            if x_generator:
                engine = x_generator.get('engine', '')
                
                if 'vulnogram' in engine.lower():
                    stats['with_vulnogram'] += 1
                    stats['vulnogram_versions'][engine] += 1
                    stats['by_cna'][cna]['vulnogram'] += 1
                    if month:
                        stats['by_month'][month]['vulnogram'] += 1
                else:
                    stats['with_other_generator'] += 1
                    stats['other_generators'][engine] += 1
                    stats['by_cna'][cna]['other_generator'] += 1
                    if month:
                        stats['by_month'][month]['other_generator'] += 1
            else:
                stats['no_generator'] += 1
                stats['by_cna'][cna]['no_generator'] += 1
                if month:
                    stats['by_month'][month]['no_generator'] += 1
                    
        except (json.JSONDecodeError, KeyError) as e:
            continue
    
    print(f"\nScan complete:")
    print(f"  - CVEs published in 2025: {stats['total']:,}")
    print(f"  - Rejected (2025): {stats['rejected']:,}")
    print(f"  - Skipped (other years): {stats['skipped_other_year']:,}")
    print(f"  - Skipped (no date): {stats['skipped_no_date']:,}")
    
    return stats


def print_stats(stats):
    """Print summary statistics."""
    print("\n" + "="*60)
    print("VULNOGRAM ANALYSIS RESULTS FOR 2025 CVEs")
    print("="*60)
    
    total = stats['total']
    vulnogram = stats['with_vulnogram']
    other_gen = stats['with_other_generator']
    no_gen = stats['no_generator']
    
    print(f"\nTotal Published CVEs: {total:,}")
    print(f"  - With Vulnogram:       {vulnogram:,} ({vulnogram/total*100:.1f}%)")
    print(f"  - With Other Generator: {other_gen:,} ({other_gen/total*100:.1f}%)")
    print(f"  - No Generator:         {no_gen:,} ({no_gen/total*100:.1f}%)")
    print(f"  - Rejected (excluded):  {stats['rejected']:,}")
    
    print(f"\nVulnogram Versions Used:")
    for version, count in stats['vulnogram_versions'].most_common(10):
        print(f"  - {version}: {count:,}")
    
    print(f"\nOther Generators (top 15):")
    for generator, count in stats['other_generators'].most_common(15):
        display = generator if generator else "(empty string)"
        print(f"  - {display}: {count:,}")
    
    print(f"\nTop CNAs Using Vulnogram:")
    cna_vulnogram = [(cna, data['vulnogram']) for cna, data in stats['by_cna'].items()]
    cna_vulnogram.sort(key=lambda x: x[1], reverse=True)
    for cna, count in cna_vulnogram[:15]:
        if count > 0:
            total_cna = stats['by_cna'][cna]['vulnogram'] + stats['by_cna'][cna]['other_generator'] + stats['by_cna'][cna]['no_generator']
            pct = count / total_cna * 100
            print(f"  - {cna}: {count:,} ({pct:.0f}% of their CVEs)")
    
    print(f"\nTop CNAs Using Other Generators:")
    cna_other = [(cna, data['other_generator']) for cna, data in stats['by_cna'].items()]
    cna_other.sort(key=lambda x: x[1], reverse=True)
    for cna, count in cna_other[:15]:
        if count > 0:
            total_cna = stats['by_cna'][cna]['vulnogram'] + stats['by_cna'][cna]['other_generator'] + stats['by_cna'][cna]['no_generator']
            pct = count / total_cna * 100
            print(f"  - {cna}: {count:,} ({pct:.0f}% of their CVEs)")
    
    print(f"\nTop CNAs With No Generator:")
    cna_none = [(cna, data['no_generator']) for cna, data in stats['by_cna'].items()]
    cna_none.sort(key=lambda x: x[1], reverse=True)
    for cna, count in cna_none[:15]:
        if count > 0:
            total_cna = stats['by_cna'][cna]['vulnogram'] + stats['by_cna'][cna]['other_generator'] + stats['by_cna'][cna]['no_generator']
            pct = count / total_cna * 100
            print(f"  - {cna}: {count:,} ({pct:.0f}% of their CVEs)")


def graph_vulnogram_pie(stats, save_path=None):
    """
    Create a pie chart showing Vulnogram vs non-Vulnogram CVEs.
    Returns the figure object.
    """
    print("Generating: Vulnogram Usage Pie Chart...")
    
    vulnogram = stats['with_vulnogram']
    other = stats['without_vulnogram']
    total = stats['total']
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Data
    sizes = [vulnogram, other]
    labels = [
        f'With Vulnogram\n{vulnogram:,} ({vulnogram/total*100:.1f}%)',
        f'Without Vulnogram\n{other:,} ({other/total*100:.1f}%)'
    ]
    colors = [COLORS['primary'], COLORS['secondary']]
    explode = (0.02, 0)  # Slightly explode the Vulnogram slice
    
    wedges, texts = ax.pie(sizes, labels=labels, colors=colors, explode=explode,
                           startangle=90, 
                           wedgeprops=dict(width=1, edgecolor='white', linewidth=2),
                           textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    ax.set_title('2025 CVEs: Vulnogram Generator Usage', fontsize=16, fontweight='bold', pad=20)
    
    # Add total in center
    ax.text(0, 0, f'Total\n{total:,}', ha='center', va='center', 
            fontsize=14, fontweight='bold', color=COLORS['text'])
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_vulnogram_bar(stats, save_path=None):
    """
    Create a horizontal bar chart comparing Vulnogram vs Other Generators vs No Generator.
    Returns the figure object.
    """
    print("Generating: Generator Usage Bar Chart...")
    
    vulnogram = stats['with_vulnogram']
    other_gen = stats['with_other_generator']
    no_gen = stats['no_generator']
    total = stats['total']
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    categories = ['With Vulnogram', 'Other Generator', 'No Generator']
    values = [vulnogram, other_gen, no_gen]
    colors = [COLORS['primary'], COLORS['accent'], COLORS['secondary']]
    
    bars = ax.barh(categories, values, color=colors, edgecolor='white', height=0.6)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title('2025 CVEs by Generator Type', fontweight='bold')
    
    # Add value labels
    for bar, val in zip(bars, values):
        pct = val / total * 100
        ax.text(val + total * 0.01, bar.get_y() + bar.get_height()/2, 
                f'{val:,} ({pct:.1f}%)', 
                va='center', ha='left', fontsize=12, fontweight='bold',
                color=COLORS['text'])
    
    ax.set_xlim(0, max(values) * 1.25)
    ax.invert_yaxis()
    
    # Format x-axis
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_vulnogram_monthly(stats, save_path=None):
    """
    Create a stacked bar chart showing Vulnogram usage by month.
    Returns the figure object.
    """
    print("Generating: Monthly Vulnogram Usage...")
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    months = list(range(1, 13))
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    vulnogram_counts = [stats['by_month'][m]['vulnogram'] for m in months]
    other_gen_counts = [stats['by_month'][m]['other_generator'] for m in months]
    no_gen_counts = [stats['by_month'][m]['no_generator'] for m in months]
    
    # Filter to months with data
    has_data = [(m, v, o, n) for m, v, o, n in zip(month_names, vulnogram_counts, other_gen_counts, no_gen_counts) if v + o + n > 0]
    if not has_data:
        print("  No monthly data available")
        return None
    
    month_labels, vulnogram_vals, other_gen_vals, no_gen_vals = zip(*has_data)
    
    x = range(len(month_labels))
    width = 0.7
    
    # Stacked bar chart with three segments
    bars1 = ax.bar(x, vulnogram_vals, width, label='With Vulnogram', 
                   color=COLORS['primary'], edgecolor='white')
    bars2 = ax.bar(x, other_gen_vals, width, bottom=vulnogram_vals, 
                   label='Other Generator', color=COLORS['accent'], edgecolor='white')
    bottom2 = [v + o for v, o in zip(vulnogram_vals, other_gen_vals)]
    bars3 = ax.bar(x, no_gen_vals, width, bottom=bottom2, 
                   label='No Generator', color=COLORS['secondary'], edgecolor='white')
    
    ax.set_xlabel('Month')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('2025 CVEs: Generator Usage by Month', fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(month_labels)
    ax.legend(loc='upper left')
    
    # Add total labels on top
    for i, (v, o, n) in enumerate(zip(vulnogram_vals, other_gen_vals, no_gen_vals)):
        total = v + o + n
        if total > 0:
            ax.annotate(f'{total:,}', xy=(i, total), xytext=(0, 3),
                       textcoords='offset points', ha='center', va='bottom',
                       fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_top_cnas_vulnogram(stats, save_path=None, top_n=15):
    """
    Create a horizontal bar chart showing top CNAs using Vulnogram.
    Returns the figure object.
    """
    print("Generating: Top CNAs Using Vulnogram...")
    
    # Get CNAs with most Vulnogram usage
    cna_data = [(cna, data['vulnogram'], data['other_generator'], data['no_generator']) 
                for cna, data in stats['by_cna'].items() 
                if data['vulnogram'] > 0]
    cna_data.sort(key=lambda x: x[1], reverse=True)
    cna_data = cna_data[:top_n]
    
    if not cna_data:
        print("  No CNA data available")
        return None
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    cnas = [d[0] for d in cna_data]
    vulnogram_counts = [d[1] for d in cna_data]
    other_gen_counts = [d[2] for d in cna_data]
    no_gen_counts = [d[3] for d in cna_data]
    
    y = range(len(cnas))
    height = 0.7
    
    # Stacked horizontal bars with three segments
    bars1 = ax.barh(y, vulnogram_counts, height, label='With Vulnogram',
                    color=COLORS['primary'], edgecolor='white')
    bars2 = ax.barh(y, other_gen_counts, height, left=vulnogram_counts,
                    label='Other Generator', color=COLORS['accent'], edgecolor='white')
    left2 = [v + o for v, o in zip(vulnogram_counts, other_gen_counts)]
    bars3 = ax.barh(y, no_gen_counts, height, left=left2,
                    label='No Generator', color=COLORS['secondary'], edgecolor='white')
    
    ax.set_xlabel('Number of CVEs')
    ax.set_ylabel('CNA')
    ax.set_title('Top 15 CNAs Using Vulnogram Generator (2025)', fontweight='bold')
    ax.set_yticks(y)
    ax.set_yticklabels(cnas)
    ax.legend(loc='lower right')
    ax.invert_yaxis()
    
    # Add percentage labels
    for i, (v, o, n) in enumerate(zip(vulnogram_counts, other_gen_counts, no_gen_counts)):
        total = v + o + n
        pct = v / total * 100 if total > 0 else 0
        ax.text(total + 5, i, f'{pct:.0f}%', va='center', ha='left',
                fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_generator_versions(stats, save_path=None):
    """
    Create a horizontal bar chart showing Vulnogram version distribution.
    Returns the figure object.
    """
    print("Generating: Vulnogram Version Distribution...")
    
    versions = stats['vulnogram_versions'].most_common(10)
    
    if not versions:
        print("  No version data available")
        return None
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    labels = [v[0] for v in versions]
    counts = [v[1] for v in versions]
    
    # Truncate long labels
    labels = [l[:40] + '...' if len(l) > 40 else l for l in labels]
    
    y = range(len(labels))
    bars = ax.barh(y, counts, color=COLORS['primary'], edgecolor='white', height=0.7)
    
    ax.set_xlabel('Number of CVEs')
    ax.set_title('Vulnogram Version Distribution (2025 CVEs)', fontweight='bold')
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    
    # Add value labels
    for bar, count in zip(bars, counts):
        ax.text(count + max(counts) * 0.01, bar.get_y() + bar.get_height()/2,
                f'{count:,}', va='center', ha='left', fontsize=ANNOTATION_SIZE,
                color=COLORS['text'])
    
    ax.set_xlim(0, max(counts) * 1.15)
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_vulnogram_percentage_by_cna(stats, save_path=None, min_cves=50, top_n=20):
    """
    Create a horizontal bar chart showing percentage of Vulnogram usage per CNA.
    Only includes CNAs with at least min_cves total CVEs.
    Returns the figure object.
    """
    print("Generating: Vulnogram Adoption Rate by CNA...")
    
    # Get CNAs with enough CVEs
    cna_data = []
    for cna, data in stats['by_cna'].items():
        total = data['vulnogram'] + data['other_generator'] + data['no_generator']
        if total >= min_cves:
            pct = data['vulnogram'] / total * 100
            cna_data.append((cna, pct, total, data['vulnogram']))
    
    if not cna_data:
        print(f"  No CNAs with at least {min_cves} CVEs")
        return None
    
    # Sort by percentage descending
    cna_data.sort(key=lambda x: x[1], reverse=True)
    cna_data = cna_data[:top_n]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    cnas = [d[0] for d in cna_data]
    percentages = [d[1] for d in cna_data]
    totals = [d[2] for d in cna_data]
    
    y = range(len(cnas))
    
    # Color bars based on percentage
    colors = [COLORS['primary'] if p >= 50 else COLORS['secondary'] for p in percentages]
    
    bars = ax.barh(y, percentages, color=colors, edgecolor='white', height=0.7)
    
    ax.set_xlabel('Vulnogram Usage (%)')
    ax.set_title(f'Vulnogram Adoption Rate by CNA (min {min_cves} CVEs)', fontweight='bold')
    ax.set_yticks(y)
    ax.set_yticklabels(cnas)
    ax.invert_yaxis()
    ax.set_xlim(0, 105)
    
    # Add value labels
    for i, (bar, pct, total) in enumerate(zip(bars, percentages, totals)):
        ax.text(pct + 1, bar.get_y() + bar.get_height()/2,
                f'{pct:.0f}% ({total:,} total)', va='center', ha='left',
                fontsize=ANNOTATION_SIZE, color=COLORS['text'])
    
    # Add 50% reference line
    ax.axvline(x=50, color=COLORS['alert'], linestyle='--', linewidth=1, alpha=0.7)
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def main():
    """Main function to run the Vulnogram analysis."""
    print("="*60)
    print("VULNOGRAM GENERATOR ANALYSIS FOR 2025 CVEs")
    print("="*60)
    
    # Check if data directory exists
    if not CVE_DATA_DIR.exists():
        print(f"Error: Data directory not found: {CVE_DATA_DIR}")
        print("Please run 01_download_data.py first.")
        return
    
    # Scan CVE files
    stats = scan_2025_cves()
    
    # Print statistics
    print_stats(stats)
    
    # Generate graphs
    print("\n" + "="*60)
    print("GENERATING GRAPHS")
    print("="*60)
    
    # Main comparison chart
    graph_vulnogram_bar(stats, GRAPHS_DIR / "vulnogram_usage.png")
    
    # Monthly breakdown
    graph_vulnogram_monthly(stats, GRAPHS_DIR / "vulnogram_monthly.png")
    
    # Top CNAs using Vulnogram
    graph_top_cnas_vulnogram(stats, GRAPHS_DIR / "vulnogram_top_cnas.png")
    
    # Version distribution
    graph_generator_versions(stats, GRAPHS_DIR / "vulnogram_versions.png")
    
    # Adoption rate by CNA
    graph_vulnogram_percentage_by_cna(stats, GRAPHS_DIR / "vulnogram_adoption_rate.png")
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"\nGraphs saved to: {GRAPHS_DIR.absolute()}")
    print("  - vulnogram_usage.png")
    print("  - vulnogram_monthly.png")
    print("  - vulnogram_top_cnas.png")
    print("  - vulnogram_versions.png")
    print("  - vulnogram_adoption_rate.png")
    
    # Save stats to JSON for potential blog integration
    import json
    stats_output = {
        'total_cves': stats['total'],
        'with_vulnogram': stats['with_vulnogram'],
        'with_other_generator': stats['with_other_generator'],
        'no_generator': stats['no_generator'],
        'vulnogram_percentage': round(stats['with_vulnogram'] / stats['total'] * 100, 1),
        'other_generator_percentage': round(stats['with_other_generator'] / stats['total'] * 100, 1),
        'no_generator_percentage': round(stats['no_generator'] / stats['total'] * 100, 1),
        'rejected_excluded': stats['rejected'],
        'vulnogram_versions': dict(stats['vulnogram_versions'].most_common(10)),
        'other_generators': dict(stats['other_generators'].most_common(15)),
    }
    
    with open(GRAPHS_DIR / "vulnogram_stats.json", 'w') as f:
        json.dump(stats_output, f, indent=2)
    print("  - vulnogram_stats.json")


if __name__ == "__main__":
    main()
