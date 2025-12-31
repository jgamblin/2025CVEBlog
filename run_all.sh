#!/bin/bash
#
# 2025 CVE Data Review - Full Pipeline
# Runs all scripts in sequence to generate the complete blog
#

set -e  # Exit on any error

echo "============================================================"
echo "2025 CVE Data Review - Full Pipeline"
echo "============================================================"
echo ""

# Check for required environment variable
if [ -z "$GEMINI_API_KEY" ] && [ -z "$GOOGLE_API_KEY" ]; then
    echo "⚠️  Warning: No GEMINI_API_KEY or GOOGLE_API_KEY set"
    echo "   AI enrichment (step 5) will be skipped"
    echo ""
fi

# Step 1: Download Data
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/5] Downloading CVE Data..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 01_download_data.py
echo ""

# Step 2: Process Data
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/5] Processing CVE Data..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 02_process_data.py
echo ""

# Step 3: Generate Graphs
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/5] Generating Graphs..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 03_generate_graphs.py
echo ""

# Step 4: Generate Blog
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/5] Generating Blog..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 04_generate_blog.py
echo ""

# Step 5: Enrich with AI (optional - requires API key)
if [ -n "$GEMINI_API_KEY" ] || [ -n "$GOOGLE_API_KEY" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[5/5] Enriching Blog with AI..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    python3 05_enrich_blog.py
    echo ""
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[5/5] Skipping AI Enrichment (no API key)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
fi

# Summary
echo "============================================================"
echo "✅ PIPELINE COMPLETE!"
echo "============================================================"
echo ""
echo "Generated files:"
echo "  📄 blog.md           - Main blog post"
if [ -f "blog_enriched.md" ]; then
    echo "  📄 blog_enriched.md  - AI-enhanced version"
fi
echo "  📊 graphs/           - All visualizations"
echo ""
echo "Graph count: $(ls -1 graphs/*.png 2>/dev/null | wc -l | tr -d ' ') images"
echo ""
