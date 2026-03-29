# 2025 CVE Data Review

[![CI](https://github.com/jgamblin/2025CVEBlog/actions/workflows/ci.yml/badge.svg)](https://github.com/jgamblin/2025CVEBlog/actions/workflows/ci.yml)

Annual review of CVE (Common Vulnerabilities and Exposures) data for 2025. This project downloads, processes, and visualizes CVE data from multiple authoritative sources to produce a publication-ready blog post with professional graphs.

## Data Sources

1. **NVD JSON** - National Vulnerability Database export from https://nvd.handsonhacking.org/nvd.json
2. **CVE List V5** - Official CVE records from https://github.com/CVEProject/cvelistV5

## Requirements

- Python 3.11+
- Dependencies listed in `requirements.txt`
- (Optional) `GEMINI_API_KEY` or `GOOGLE_API_KEY` for AI blog enrichment

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full pipeline (download, process, graph, blog, enrich)
./run_all.sh

# Or run individual steps:
python 01_download_data.py       # Download data (~1GB+ NVD JSON)
python 02_process_data.py        # Parse into analysis-ready DataFrames
python 03_generate_graphs.py     # Generate visualizations (standalone)
python 04_generate_blog.py       # Generate blog.md with all graphs
python 05_enrich_blog.py         # AI-enhanced blog (requires API key)
python 06_vulnogram_analysis.py  # Vulnogram adoption analysis
python 07_windows_historical_analysis.py  # Windows CVE historical trends
```

## Project Structure

```
2025CVEBlog/
├── 01_download_data.py      # Downloads NVD JSON and clones CVE List V5
├── 02_process_data.py       # Parses data into DataFrames
├── 03_generate_graphs.py    # Generates visualizations (standalone)
├── 04_generate_blog.py      # Generates blog.md with all graphs
├── 05_enrich_blog.py        # AI-enhanced blog enrichment
├── 06_vulnogram_analysis.py # Vulnogram adoption analysis
├── 07_windows_historical_analysis.py  # Windows CVE trends
├── style_config.py          # Unified visualization style configuration
├── run_all.sh               # Full pipeline runner
├── requirements.txt         # Python dependencies
├── tests/                   # Test suite
├── blog.md                  # Generated blog post (output)
├── data/                    # Downloaded raw data (gitignored)
├── processed/               # Processed DataFrames (gitignored)
├── graphs/                  # Generated visualizations
└── OldBlogs/                # Previous year blog PDFs
```

## Graphs Generated

1. **CVEs by Year** - Historical count of CVEs published each year
2. **Year-over-Year Growth** - Annual growth rate percentage
3. **Cumulative Growth** - Running total of all CVEs
4. **2025 Monthly Distribution** - CVEs published each month in 2025
5. **CVSS Score Distribution** - Histogram of severity scores
6. **Severity Breakdown** - Pie/bar chart of Critical/High/Medium/Low
7. **Top CWEs** - Most common weakness types
8. **Top CNAs** - Most active CVE Numbering Authorities
9. **Data Quality** - Coverage of CVSS, CWE, CPE over time
10. **Top Vendors** - Vendors with most CVEs
11. **CVSS by Year** - Score comparison across years

## Testing

```bash
pytest tests/ -v
```

## Output

Running `04_generate_blog.py` (or `./run_all.sh`) produces:

- `blog.md` - A complete, publishable Markdown blog post
- `blog_enriched.md` - AI-enhanced version (if API key is set)
- `graphs/*.png` - All visualizations embedded in the blog

## License

[Apache 2.0](LICENSE)
