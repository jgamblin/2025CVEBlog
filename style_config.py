#!/usr/bin/env python3
"""
Unified Style Configuration for 2025 CVE Data Review
Professional "Journalism" style for publication-ready visualizations
"""

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# =============================================================================
# FIGURE DIMENSIONS
# =============================================================================
FIG_SIZE = (12, 6)           # Standard for all single charts
FIG_SIZE_TALL = (12, 8)      # For horizontal bar charts with many items
FIG_SIZE_DOUBLE = (14, 6)    # For side-by-side charts

# =============================================================================
# COLOR PALETTE - Professional Blue/Grey with Alert Red
# =============================================================================
COLORS = {
    # Primary palette
    'primary': '#1e3a5f',      # Deep Navy - main bars/lines
    'secondary': '#64748b',    # Slate - secondary elements
    'accent': '#3d6a99',       # Medium blue - tertiary elements
    
    # Alert/highlight
    'alert': '#dc2626',        # High-contrast Red - current year/alerts
    
    # Neutral tones
    'neutral': '#94a3b8',      # Light slate - muted elements
    'light': '#cbd5e1',        # Very light slate - backgrounds
    'text': '#1e293b',         # Dark slate - text
    'grid': '#e2e8f0',         # Light grey - gridlines
}

# Severity colors - muted professional palette
SEVERITY_COLORS = {
    'CRITICAL': '#0c2340',     # Darkest navy
    'HIGH': '#1e3a5f',         # Dark navy
    'MEDIUM': '#3d6a99',       # Medium blue
    'LOW': '#6b9dc9',          # Light blue
    'NONE': '#94a3b8'          # Slate grey
}

# =============================================================================
# TYPOGRAPHY
# =============================================================================
TITLE_SIZE = 16
LABEL_SIZE = 12
TICK_SIZE = 10
ANNOTATION_SIZE = 9
LEGEND_SIZE = 10

# =============================================================================
# OUTPUT SETTINGS
# =============================================================================
SAVE_DPI = 300

# =============================================================================
# CWE NAMES MAPPING
# =============================================================================
CWE_NAMES = {
    'CWE-79': 'XSS',
    'CWE-89': 'SQL Injection',
    'CWE-787': 'OOB Write',
    'CWE-125': 'OOB Read',
    'CWE-20': 'Input Validation',
    'CWE-22': 'Path Traversal',
    'CWE-352': 'CSRF',
    'CWE-78': 'Command Injection',
    'CWE-416': 'Use After Free',
    'CWE-190': 'Integer Overflow',
    'CWE-476': 'NULL Pointer',
    'CWE-119': 'Buffer Overflow',
    'CWE-200': 'Info Exposure',
    'CWE-400': 'Resource Exhaustion',
    'CWE-434': 'File Upload',
    'CWE-863': 'Auth Bypass',
    'CWE-918': 'SSRF',
    'CWE-94': 'Code Injection',
    'CWE-502': 'Deserialization',
    'CWE-287': 'Auth Issues',
    'CWE-269': 'Privilege Management',
    'CWE-77': 'Command Injection',
    'CWE-276': 'Default Permissions',
    'CWE-862': 'Missing Authorization',
    'CWE-121': 'Stack Buffer Overflow',
    'CWE-74': 'Injection',
    'CWE-79': 'XSS',
    'CWE-120': 'Buffer Copy',
    'CWE-306': 'Missing Auth',
    'CWE-798': 'Hardcoded Creds',
    'CWE-732': 'Incorrect Permissions',
    'NVD-CWE-noinfo': 'No Info',
    'NVD-CWE-Other': 'Other'
}

# =============================================================================
# MATPLOTLIB RCPARAMS - Apply globally
# =============================================================================
def apply_style():
    """Apply the professional journalism style to matplotlib"""
    plt.rcParams.update({
        # Font settings - Arial/Helvetica preference
        'font.family': 'sans-serif',
        'font.sans-serif': ['Arial', 'Helvetica', 'DejaVu Sans', 'sans-serif'],
        'font.size': TICK_SIZE,
        
        # Title settings
        'axes.titlesize': TITLE_SIZE,
        'axes.titleweight': 'bold',
        'axes.titlepad': 15,
        
        # Label settings
        'axes.labelsize': LABEL_SIZE,
        'axes.labelweight': 'bold',
        'axes.labelpad': 8,
        
        # Spine settings - clean look, no top/right
        'axes.spines.top': False,
        'axes.spines.right': False,
        'axes.spines.left': True,
        'axes.spines.bottom': True,
        'axes.edgecolor': COLORS['secondary'],
        'axes.linewidth': 0.8,
        
        # Background - clean white
        'axes.facecolor': 'white',
        'figure.facecolor': 'white',
        'figure.edgecolor': 'white',
        'savefig.facecolor': 'white',
        'savefig.edgecolor': 'white',
        
        # Grid - light grey, y-axis only by default
        'axes.grid': True,
        'axes.grid.axis': 'y',
        'grid.color': COLORS['grid'],
        'grid.linewidth': 0.5,
        'grid.alpha': 0.7,
        'grid.linestyle': '-',
        
        # Tick settings
        'xtick.labelsize': TICK_SIZE,
        'ytick.labelsize': TICK_SIZE,
        'xtick.color': COLORS['text'],
        'ytick.color': COLORS['text'],
        'xtick.direction': 'out',
        'ytick.direction': 'out',
        
        # Legend settings
        'legend.fontsize': LEGEND_SIZE,
        'legend.frameon': True,
        'legend.framealpha': 0.9,
        'legend.edgecolor': COLORS['light'],
        'legend.facecolor': 'white',
        
        # Figure settings
        'figure.titlesize': TITLE_SIZE,
        'figure.titleweight': 'bold',
        'figure.dpi': 100,
        'savefig.dpi': SAVE_DPI,
        'savefig.bbox': 'tight',
        'savefig.pad_inches': 0.1,
    })


def format_thousands(x, pos):
    """Format axis labels with K suffix for thousands"""
    if x >= 1000:
        return f'{int(x/1000)}K'
    return f'{int(x)}'


def get_thousands_formatter():
    """Return a FuncFormatter for thousands"""
    return ticker.FuncFormatter(format_thousands)


# Watermark settings
WATERMARK_TEXT = '@jgamblin'
WATERMARK_ALPHA = 0.5


def save_figure(fig, filepath, dpi=None):
    """Save figure with consistent settings and watermark"""
    if dpi is None:
        dpi = SAVE_DPI
    
    # Add watermark to lower right corner
    fig.text(0.98, 0.02, WATERMARK_TEXT, 
             transform=fig.transFigure,
             fontsize=10, color=COLORS['secondary'],
             alpha=WATERMARK_ALPHA,
             ha='right', va='bottom',
             fontweight='bold',
             fontstyle='italic')
    
    fig.savefig(filepath, dpi=dpi, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)


# Apply style on import
apply_style()
