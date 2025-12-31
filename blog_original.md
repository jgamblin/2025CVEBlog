# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

Another year, another record-breaking year for CVE disclosures. In this annual review, I analyze the Common Vulnerabilities and Exposures (CVE) data for 2025, examining trends in vulnerability disclosures, severity distributions, and the organizations driving vulnerability documentation.

## Executive Summary

**2025 saw 48,124 CVEs published**, an increase of **20.4%** compared to 39,962 CVEs in 2024. This brings the all-time total to **308,859 CVEs** since the program began in 1999.

> **Note**: All statistics in this report exclude rejected CVEs to provide an accurate count of active vulnerabilities.

### Key Statistics at a Glance

| Metric | Value |
|--------|-------|
| **Total CVEs in 2025** | **48,124** |
| Year-over-Year Change | +20.4% |
| Critical Severity | 3,980 |
| High Severity | 14,978 |
| Average CVSS Score | 6.60 |
| CVSS Coverage | 91.3% |
| CWE Coverage | 92.3% |
| Active CNAs | 365 |
| Rejected CVEs (2025) | 1,787 |

---

## Historical CVE Growth

The number of CVEs published each year continues its upward trajectory. 2025 marks another year of significant growth in vulnerability disclosures.

![CVEs by Year](graphs/01_cves_by_year.png)

The growth isn't uniform—some years saw dramatic increases while others showed modest growth or even slight declines. The year-over-year growth rate provides a clearer picture of these fluctuations.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

Looking at the cumulative total, we've now surpassed **308,180 CVEs** in the database.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---

## 2025 Monthly Distribution

CVE publications varied throughout 2025, with **Dec** being the peak month at **5,439 CVEs**.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

---

## CVSS Score Analysis

The Common Vulnerability Scoring System (CVSS) helps standardize severity assessments. Here's how 2025 CVEs were distributed across the scoring range.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The **average CVSS score for 2025 was 6.60**, with a **median of 6.50**.

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3,980 | 8.3% |
| High | 14,978 | 31.1% |
| Medium | 25,517 | 53.0% |
| Low | 1,557 | 3.2% |

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
| 1 | CWE-79 | XSS | 8,183 |
| 2 | CWE-74 |  | 2,559 |
| 3 | CWE-862 | Missing Authorization | 2,215 |
| 4 | CWE-352 | CSRF | 1,893 |
| 5 | CWE-89 | SQL Injection | 1,704 |

---

## CVE Numbering Authorities (CNAs)

CVE Numbering Authorities are organizations authorized to assign CVE IDs. The ecosystem continues to grow with more organizations participating in coordinated vulnerability disclosure.

![Top CNAs](graphs/08_top_cnas.png)

### Top 5 CNAs in 2025

| Rank | CNA | CVEs Assigned |
|------|-----|---------------|
| 1 | Patchstack | 7,007 |
| 2 | VulDB | 5,902 |
| 3 | Linux | 5,686 |
| 4 | mitre | 5,207 |
| 5 | Wordfence | 3,451 |

In total, **365 unique CNAs** assigned CVEs in 2025.

---

## Top Vendors

Which vendors had the most CVEs assigned to their products in 2025?

![Top Vendors](graphs/14_top_vendors.png)

### Top 5 Vendors in 2025

| Rank | Vendor | CVE Count |
|------|--------|-----------|
| 1 | linux | 5,687 |
| 2 | n/a | 5,310 |
| 3 | microsoft | 1,255 |
| 4 | adobe | 829 |
| 5 | code-projects | 730 |

---

## Data Quality

Not all CVEs have complete metadata. Here's how data quality has evolved over the years:

![Data Quality](graphs/09_data_quality.png)

### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.5% |

---

## Rejected CVEs

Not all CVE IDs remain active—some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the CVE ecosystem's quality control.

![Rejected CVEs](graphs/10_rejected_cves.png)

### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

CVE rejections occur for several reasons:
- **Duplicates**: The same vulnerability assigned multiple CVE IDs
- **Disputes**: Vendor disagreement that the issue is a vulnerability  
- **Invalid**: Not a security vulnerability or insufficient information
- **Withdrawn**: CVE withdrawn by the assigning CNA

---

## Conclusions

### Key Takeaways from 2025

1. **Volume continues to grow**: With 48,124 CVEs, 2025 set a new record in vulnerability disclosures.

2. **Severity remains concerning**: 18,958 CVEs (39.4%) were rated Critical or High severity.

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
