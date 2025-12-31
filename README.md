# 2025 CVE Data Review

Annual review of CVE (Common Vulnerabilities and Exposures) data for 2025.

## Data Sources

1. **NVD JSON** - National Vulnerability Database export from https://nvd.handsonhacking.org/nvd.json
2. **CVE List V5** - Official CVE records from https://github.com/CVEProject/cvelistV5

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Download data (this will take a while - NVD JSON is ~1GB+)
python 01_download_data.py

# Process data into analysis-ready format
python 02_process_data.py

# Generate the blog post with all graphs
python 04_generate_blog.py
```

## Project Structure

```
2025CVEBlog/
├── 01_download_data.py      # Downloads NVD JSON and clones CVE List V5
├── 02_process_data.py       # Parses data into DataFrames
├── 03_generate_graphs.py    # Generates visualizations (standalone)
├── 04_generate_blog.py      # Generates blog.md with all graphs
├── requirements.txt         # Python dependencies
├── blog.md                  # Generated blog post (output)
├── data/                    # Downloaded raw data
│   ├── nvd.json
│   └── cvelistV5/
├── processed/               # Processed DataFrames
│   ├── nvd_cves.parquet
│   ├── cvelist_v5.parquet
│   └── cna_stats.csv
├── graphs/                  # Generated visualizations
│   ├── 01_cves_by_year.png
│   ├── 02_yoy_growth.png
│   └── ...
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

## Output

Running `04_generate_blog.py` produces:
- `blog.md` - A complete, publishable Markdown blog post
- `graphs/*.png` - All visualizations embedded in the blog

## License

Apache 2.0
