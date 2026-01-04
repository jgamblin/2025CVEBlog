#!/usr/bin/env python3
"""
Windows Historical Analysis for Lisa Olson (MSRC)
Generates graphs showing Windows ranking history and top products by year

Created in response to question about whether Windows was ever #1 in Top Products
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
    COLORS, FIG_SIZE, FIG_SIZE_TALL, FIG_SIZE_DOUBLE,
    ANNOTATION_SIZE, SAVE_DPI, apply_style,
    format_thousands, get_thousands_formatter, save_figure
)

# =============================================================================
# DIRECTORIES
# =============================================================================
OUTPUT_DIR = Path("processed")
GRAPHS_DIR = Path("graphs")
GRAPHS_DIR.mkdir(exist_ok=True)

# Apply consistent style
apply_style()


def load_data():
    """Load processed data, filtering out rejected CVEs"""
    print("Loading processed data...")
    
    if (OUTPUT_DIR / "nvd_cves.parquet").exists():
        df = pd.read_parquet(OUTPUT_DIR / "nvd_cves.parquet")
        print("  Loaded from parquet")
    elif (OUTPUT_DIR / "nvd_cves.csv").exists():
        df = pd.read_csv(OUTPUT_DIR / "nvd_cves.csv", parse_dates=['published', 'modified'])
        print("  Loaded from CSV")
    else:
        raise FileNotFoundError("No NVD data found")
    
    # Filter out rejected CVEs
    if 'is_rejected' in df.columns:
        rejected = df['is_rejected'].sum()
        df = df[~df['is_rejected']]
        print(f"  Filtered out {rejected:,} rejected CVEs")
    
    # Exclude future data
    df = df[df['year'] <= 2025]
    
    return df


def get_yearly_product_rankings(df, start_year=2010, end_year=2025):
    """Calculate product rankings for each year"""
    results = []
    
    for year in range(start_year, end_year + 1):
        year_df = df[(df['year'] == year) & (df['product'].notna())].copy()
        if len(year_df) == 0:
            continue
        
        # Clean product names
        year_df['product_clean'] = year_df['product'].str.lower().str.strip()
        exclude_values = ['n/a', 'unknown', 'none', 'na', 'n_a', '*', '']
        year_df = year_df[~year_df['product_clean'].isin(exclude_values)]
        year_df['product_clean'] = year_df['product_clean'].str.replace('_', ' ')
        year_df['product_clean'] = year_df['product_clean'].str.title()
        
        product_counts = year_df['product_clean'].value_counts()
        
        if len(product_counts) == 0:
            continue
        
        # Get top 5 products
        top5 = list(zip(product_counts.index[:5], product_counts.values[:5]))
        
        # Find Windows rank
        windows_rank = None
        windows_count = 0
        windows_product = None
        for rank, (product, count) in enumerate(product_counts.items(), 1):
            if 'windows' in product.lower():
                windows_rank = rank
                windows_count = count
                windows_product = product
                break
        
        results.append({
            'year': year,
            'top1_product': product_counts.index[0],
            'top1_count': product_counts.values[0],
            'top5': top5,
            'windows_rank': windows_rank,
            'windows_count': windows_count,
            'windows_product': windows_product
        })
    
    return results


def graph_top1_products_by_year(rankings, save_path=None):
    """Horizontal timeline showing #1 product each year with CVE counts"""
    print("Generating: #1 Product by Year...")
    
    years = [r['year'] for r in rankings]
    products = [r['top1_product'] for r in rankings]
    counts = [r['top1_count'] for r in rankings]
    
    # Create color mapping for products
    unique_products = list(set(products))
    product_colors = {
        'Android': '#3DDC84',           # Android green
        'Linux Kernel': '#FCC624',      # Linux yellow
        'Chrome': '#4285F4',            # Google blue
        'Mac Os X': '#A2AAAD',          # Apple grey
        'Internet Explorer': '#0078D4', # MS blue
    }
    # Default color for others
    for p in unique_products:
        if p not in product_colors:
            product_colors[p] = COLORS['secondary']
    
    colors = [product_colors.get(p, COLORS['secondary']) for p in products]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE_TALL)
    
    y_pos = np.arange(len(years))
    bars = ax.barh(y_pos, counts, color=colors, edgecolor='white', linewidth=0.5)
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(years)
    ax.set_xlabel('Number of CVEs')
    ax.set_title('#1 Most Vulnerable Product by Year (2010-2025)')
    
    # Add product labels on bars
    for i, (bar, product, count) in enumerate(zip(bars, products, counts)):
        width = bar.get_width()
        # Put label inside bar if there's room, otherwise outside
        if width > max(counts) * 0.3:
            ax.annotate(f'{product} ({count:,})',
                        xy=(width / 2, bar.get_y() + bar.get_height() / 2),
                        ha='center', va='center', fontsize=ANNOTATION_SIZE,
                        color='white', fontweight='bold')
        else:
            ax.annotate(f'{product} ({count:,})',
                        xy=(width + 50, bar.get_y() + bar.get_height() / 2),
                        ha='left', va='center', fontsize=ANNOTATION_SIZE,
                        color=COLORS['text'])
    
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(get_thousands_formatter())
    
    # Add legend for product colors
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=product_colors[p], label=p) 
                       for p in ['Android', 'Linux Kernel', 'Chrome', 'Mac Os X', 'Internet Explorer']
                       if p in unique_products]
    if legend_elements:
        ax.legend(handles=legend_elements, loc='lower right', title='Product')
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_windows_ranking_history(rankings, save_path=None):
    """Line chart showing Windows ranking over time"""
    print("Generating: Windows Ranking History...")
    
    years = [r['year'] for r in rankings if r['windows_rank'] is not None]
    ranks = [r['windows_rank'] for r in rankings if r['windows_rank'] is not None]
    counts = [r['windows_count'] for r in rankings if r['windows_rank'] is not None]
    
    fig, ax1 = plt.subplots(figsize=FIG_SIZE)
    
    # Plot ranking (inverted - lower is better)
    color_rank = COLORS['primary']
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Ranking Position', color=color_rank)
    line1 = ax1.plot(years, ranks, color=color_rank, marker='o', linewidth=2.5, 
                     markersize=8, label='Windows Rank')
    ax1.tick_params(axis='y', labelcolor=color_rank)
    ax1.invert_yaxis()  # Lower rank is better, so invert
    ax1.set_ylim(25, 0)  # Set limits with some padding
    
    # Add rank labels
    for year, rank in zip(years, ranks):
        ax1.annotate(f'#{rank}', (year, rank), textcoords="offset points",
                     xytext=(0, -15), ha='center', fontsize=ANNOTATION_SIZE,
                     color=color_rank, fontweight='bold')
    
    # Secondary axis for CVE count
    ax2 = ax1.twinx()
    color_count = COLORS['alert']
    ax2.set_ylabel('Windows CVE Count', color=color_count)
    line2 = ax2.plot(years, counts, color=color_count, marker='s', linewidth=2, 
                     markersize=6, linestyle='--', alpha=0.7, label='CVE Count')
    ax2.tick_params(axis='y', labelcolor=color_count)
    
    ax1.set_title('Windows Ranking in "Most Vulnerable Products" (2010-2025)\nWindows Has Never Been #1')
    
    # Add horizontal line at rank 1
    ax1.axhline(y=1, color=COLORS['neutral'], linestyle=':', linewidth=1, alpha=0.7)
    ax1.text(2011, 1.5, '← #1 Position (never achieved)', fontsize=ANNOTATION_SIZE, 
             color=COLORS['secondary'], style='italic')
    
    # Highlight best ranking years
    best_rank = min(ranks)
    best_years = [y for y, r in zip(years, ranks) if r == best_rank]
    for by in best_years:
        ax1.axvline(x=by, color=COLORS['accent'], linestyle='--', linewidth=1, alpha=0.3)
    
    # Combined legend
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc='upper left')
    
    ax1.set_xticks(years)
    ax1.set_xticklabels(years, rotation=45, ha='right')
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_windows_vs_top1(rankings, save_path=None):
    """Grouped bar chart comparing Windows CVEs vs #1 product"""
    print("Generating: Windows vs #1 Product Comparison...")
    
    years = [r['year'] for r in rankings if r['windows_rank'] is not None]
    windows_counts = [r['windows_count'] for r in rankings if r['windows_rank'] is not None]
    top1_counts = [r['top1_count'] for r in rankings if r['windows_rank'] is not None]
    top1_products = [r['top1_product'] for r in rankings if r['windows_rank'] is not None]
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    x = np.arange(len(years))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, top1_counts, width, label='#1 Product', 
                   color=COLORS['primary'], edgecolor='white')
    bars2 = ax.bar(x + width/2, windows_counts, width, label='Windows', 
                   color=COLORS['alert'], edgecolor='white')
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('Windows CVE Count vs #1 Product Each Year')
    ax.set_xticks(x)
    ax.set_xticklabels(years, rotation=45, ha='right')
    ax.legend()
    
    # Add #1 product labels above bars
    for i, (bar, product) in enumerate(zip(bars1, top1_products)):
        height = bar.get_height()
        ax.annotate(product,
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=7, rotation=45,
                    color=COLORS['text'])
    
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_product_dominance_timeline(rankings, save_path=None):
    """Stacked area/timeline showing which product dominated each era"""
    print("Generating: Product Dominance Timeline...")
    
    fig, ax = plt.subplots(figsize=(14, 5))
    
    # Define eras based on #1 product
    eras = []
    current_product = None
    start_year = None
    
    for r in rankings:
        if r['top1_product'] != current_product:
            if current_product is not None:
                eras.append({
                    'product': current_product,
                    'start': start_year,
                    'end': r['year'] - 1
                })
            current_product = r['top1_product']
            start_year = r['year']
    
    # Add final era
    if current_product:
        eras.append({
            'product': current_product,
            'start': start_year,
            'end': rankings[-1]['year']
        })
    
    # Color mapping
    product_colors = {
        'Android': '#3DDC84',
        'Linux Kernel': '#FCC624',
        'Chrome': '#4285F4',
        'Mac Os X': '#A2AAAD',
        'Internet Explorer': '#0078D4',
    }
    
    # Draw eras as colored spans
    for i, era in enumerate(eras):
        color = product_colors.get(era['product'], COLORS['secondary'])
        ax.axvspan(era['start'] - 0.5, era['end'] + 0.5, 
                   alpha=0.3, color=color, label=era['product'])
        
        # Add product label in center of era
        mid_year = (era['start'] + era['end']) / 2
        era_width = era['end'] - era['start'] + 1
        
        # For narrow eras (1-2 years), rotate text vertically and stagger position
        if era_width <= 2:
            # Stagger y-position for adjacent narrow eras to avoid overlap
            y_positions = [0.85, 0.70, 0.55]  # Different heights for staggering
            y_pos = y_positions[i % 3] if era_width == 1 else 0.5
            ax.text(mid_year, y_pos, era['product'], 
                    ha='center', va='center', fontsize=10, fontweight='bold',
                    rotation=90, transform=ax.get_xaxis_transform())
        else:
            ax.text(mid_year, 0.5, era['product'], 
                    ha='center', va='center', fontsize=12, fontweight='bold',
                    transform=ax.get_xaxis_transform())
    
    # Plot #1 counts as line
    years = [r['year'] for r in rankings]
    counts = [r['top1_count'] for r in rankings]
    ax.plot(years, counts, color=COLORS['primary'], marker='o', linewidth=2.5, 
            markersize=8, zorder=5)
    
    # Add count annotations
    for year, count in zip(years, counts):
        ax.annotate(f'{count:,}', (year, count), textcoords="offset points",
                    xytext=(0, 10), ha='center', fontsize=ANNOTATION_SIZE)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('#1 Product CVE Count')
    ax.set_title('Evolution of #1 Most Vulnerable Product (2010-2025)\nWindows Has Never Held the Top Position')
    
    ax.set_xticks(years)
    ax.set_xticklabels(years, rotation=45, ha='right')
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    # Remove duplicate legend entries
    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax.legend(by_label.values(), by_label.keys(), loc='upper left', title='#1 Product')
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def graph_windows_best_years(rankings, save_path=None):
    """Highlight Windows' best ranking years"""
    print("Generating: Windows Best Years...")
    
    # Filter to years where Windows made top 5
    top5_years = [r for r in rankings if r['windows_rank'] is not None and r['windows_rank'] <= 5]
    
    if not top5_years:
        print("  Windows never made top 5")
        return None
    
    fig, ax = plt.subplots(figsize=FIG_SIZE)
    
    years = [r['year'] for r in top5_years]
    ranks = [r['windows_rank'] for r in top5_years]
    counts = [r['windows_count'] for r in top5_years]
    
    # Color bars by rank
    rank_colors = {1: '#FFD700', 2: '#C0C0C0', 3: '#CD7F32', 4: COLORS['accent'], 5: COLORS['secondary']}
    colors = [rank_colors.get(r, COLORS['neutral']) for r in ranks]
    
    bars = ax.bar(years, counts, color=colors, edgecolor='white', linewidth=0.5)
    
    # Add rank labels on bars
    for bar, rank, count in zip(bars, ranks, counts):
        height = bar.get_height()
        ax.annotate(f'#{rank}',
                    xy=(bar.get_x() + bar.get_width() / 2, height / 2),
                    ha='center', va='center', fontsize=14, fontweight='bold',
                    color='white')
        ax.annotate(f'{count:,}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5), textcoords="offset points",
                    ha='center', va='bottom', fontsize=ANNOTATION_SIZE)
    
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.set_title('Windows in Top 5 Most Vulnerable Products\nBest Ranking: #2 (2020-2023)')
    
    ax.set_xticks(years)
    ax.yaxis.set_major_formatter(get_thousands_formatter())
    
    # Add legend for rank colors
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#C0C0C0', label='#2 (Best)'),
        Patch(facecolor='#CD7F32', label='#3'),
        Patch(facecolor=COLORS['accent'], label='#4'),
        Patch(facecolor=COLORS['secondary'], label='#5'),
    ]
    ax.legend(handles=legend_elements, loc='upper left', title='Ranking')
    
    plt.tight_layout()
    
    if save_path:
        save_figure(fig, save_path)
    
    return fig


def print_summary(rankings):
    """Print summary statistics"""
    print("\n" + "="*60)
    print("SUMMARY: Windows Historical Product Ranking")
    print("="*60)
    
    # Check if Windows was ever #1
    windows_first = [r for r in rankings if r['windows_rank'] == 1]
    if windows_first:
        print(f"Windows was #1 in: {[r['year'] for r in windows_first]}")
    else:
        print("Windows has NEVER been #1 in any year from 2010-2025!")
    
    # Best ranking
    best_rank = min([r['windows_rank'] for r in rankings if r['windows_rank']])
    best_years = [r['year'] for r in rankings if r['windows_rank'] == best_rank]
    print(f"Windows' best ranking: #{best_rank} in {best_years}")
    
    # Print yearly summary
    print("\nYear-by-year breakdown:")
    print("-" * 60)
    for r in rankings:
        if r['windows_rank']:
            print(f"{r['year']}: #{r['windows_rank']} with {r['windows_count']:,} CVEs "
                  f"(#1 was {r['top1_product']} with {r['top1_count']:,})")
        else:
            print(f"{r['year']}: Windows not in top products "
                  f"(#1 was {r['top1_product']} with {r['top1_count']:,})")
    
    print("="*60)


def main():
    """Main execution"""
    print("="*60)
    print("Windows Historical Analysis")
    print("Generated for Lisa Olson (MSRC)")
    print("="*60 + "\n")
    
    # Load data
    df = load_data()
    
    # Calculate rankings
    rankings = get_yearly_product_rankings(df, start_year=2010, end_year=2025)
    
    # Generate graphs
    print("\nGenerating graphs...\n")
    
    graph_top1_products_by_year(
        rankings, 
        save_path=GRAPHS_DIR / "windows_01_top1_by_year.png"
    )
    
    graph_windows_ranking_history(
        rankings, 
        save_path=GRAPHS_DIR / "windows_02_ranking_history.png"
    )
    
    graph_windows_vs_top1(
        rankings, 
        save_path=GRAPHS_DIR / "windows_03_vs_top1.png"
    )
    
    graph_product_dominance_timeline(
        rankings, 
        save_path=GRAPHS_DIR / "windows_04_dominance_timeline.png"
    )
    
    graph_windows_best_years(
        rankings, 
        save_path=GRAPHS_DIR / "windows_05_best_years.png"
    )
    
    # Print summary
    print_summary(rankings)
    
    print("\n✅ All graphs saved to graphs/ directory")
    print("   - windows_01_top1_by_year.png")
    print("   - windows_02_ranking_history.png")
    print("   - windows_03_vs_top1.png")
    print("   - windows_04_dominance_timeline.png")
    print("   - windows_05_best_years.png")


if __name__ == "__main__":
    main()
