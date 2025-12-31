# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

Another year, another record-breaking year for CVE disclosures. In this annual review, I analyze the [Common Vulnerabilities and Exposures](https://cve.mitre.org/) (CVE) data for 2025, examining trends in vulnerability disclosures, severity distributions, and the organizations driving vulnerability documentation. I'm seeing shifts in who is reporting and what types of weaknesses are most prevalent. Let's dive in.
## Executive Summary

**2025 saw 48,124 CVEs published**, an increase of **20.4%** compared to 39,962 CVEs in 2024. This brings the all-time total to **308,859 CVEs** since the program began in 1999. I'm seeing a continued upward trend, and expect this to continue.

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

The number of [CVEs](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) published each year continues its upward trajectory. 2025 marks another year of significant growth in vulnerability disclosures. We are seeing more vulnerabilities, and faster disclosure.

![CVEs by Year](graphs/01_cves_by_year.png)

The growth isn't uniform—some years saw dramatic increases while others showed modest growth or even slight declines. The year-over-year growth rate provides a clearer picture of these fluctuations. I'm watching to see if disclosure fatigue impacts patching.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

Looking at the cumulative total, we've now surpassed **308,180 CVEs** in the database. It's critical to prioritize patching based on exploitability and impact.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

CVE publications varied throughout 2025. I noted a significant spike in **Dec**, reaching **5,439 CVEs**. This could indicate increased end-of-year reporting or a surge in discovered vulnerabilities.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

---
## Publication Patterns by Day of Week

I wanted to see if there were any patterns in when CVEs are published. The data shows a clear trend. **Tue** saw the most publications with **11,754 CVEs**.

![CVEs by Day of Week](graphs/16_day_of_week.png)

The "Patch Tuesday" effect from vendors like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) is clearly visible: Tuesday accounts for **11,754 CVEs**. Weekdays average **8,906** CVEs compared to weekends at **1,796**. This impacts when security teams should expect to react to new vulnerabilities like [CWE-79](https://cwe.mitre.org/data/definitions/79.html).

---
## Busiest Days of 2025

Some days saw massive spikes in [CVE](https://nvd.nist.gov/vuln/search) publications. I wanted to highlight a few observations.

![Top Days](graphs/17_top_days.png)
### Top 5 Busiest Days

| Rank | Date | CVE Count |
|------|------|----------|
| 1 | 2025-02-26 | 793 |
| 2 | 2025-12-09 | 660 |
| 3 | 2025-12-24 | 494 |
| 4 | 2025-06-10 | 485 |
| 5 | 2025-01-14 | 478 |

---


## Most Vulnerable Products

Beyond vendors, specific products with the most CVEs in 2025:

I wanted to highlight a few specific products that stood out. It's not just about the vendor ([Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) or [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google)), but the individual applications and systems.

![Top Products](graphs/18_top_products.png)
### Top 5 Products

| Rank | Product | CVE Count |
|------|---------|----------|
| 1 | Linux Kernel | 3,647 |
| 2 | Android | 509 |
| 3 | Windows 10 1507 | 435 |
| 4 | Experience Manager | 377 |
| 5 | Macos | 362 |

---


## CVSS Score Analysis

The [Common Vulnerability Scoring System (CVSS)](https://nvd.nist.gov/vuln-metrics/cvss) helps standardize severity assessments. I analyzed the 2025 CVEs and here's how they were distributed across the scoring range.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The **average CVSS score for 2025 was 6.60**, with a **median of 6.50**. This indicates most vulnerabilities are rated as medium severity.
### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3,980 | 8.3% |
| High | 14,978 | 31.1% |
| Medium | 25,517 | 53.0% |
| Low | 1,557 | 3.2% |

![Severity Breakdown](graphs/06_severity_breakdown.png)


### CVSS Trends Over Time

I've been tracking [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) scores and noticed some interesting patterns. The graph below visualizes the distribution of CVSS scores over the years.

![CVSS by Year](graphs/13_cvss_by_year.png)

---
## Top Weakness Types (CWE)

The [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) categorizes the types of security weaknesses. I analyzed the data and these were the most prevalent weakness types we saw exploited in 2025:

![Top CWEs](graphs/07_top_cwes.png)

[CWE-79](https://cwe.mitre.org/data/definitions/79.html), Cross-Site Scripting, remains a top issue. We also noted a rise in [CWE-89](https://cwe.mitre.org/data/definitions/89.html), SQL Injection, likely due to increased exploitation of legacy systems.
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

CVE Numbering Authorities are organizations authorized to assign [CVE](https://www.cve.org/) IDs. The ecosystem continues to grow; more organizations are participating in coordinated vulnerability disclosure. This impacts vulnerability management positively.

I'm tracking CNA participation.

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

Which vendors had the most CVEs assigned to their products in 2025? I took a look and here's what I found.

[Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) topped the list.

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

Not all [CVE](https://www.cve.org/) entries have complete metadata. This impacts our ability to effectively analyze and remediate vulnerabilities. Here's how data quality has evolved over the years:

![Data Quality](graphs/09_data_quality.png)
### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.5% |

---


## Rejected CVEs

Not all [CVE](https://www.cve.org/) IDs remain active—some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the [CVE](https://www.cve.org/) ecosystem's quality control. I find this data helps calibrate my own vulnerability research.

![Rejected CVEs](graphs/10_rejected_cves.png)
### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

I've been tracking [CVE](https://nvd.nist.gov/vuln/search) rejections closely. In 2025, we saw 1,787 CVEs rejected, representing 3.58% of all CVEs processed. This is part of a larger trend, with a total of 16,357 CVEs rejected to date.

CVE rejections occur for several reasons:
- **Duplicates**: The same vulnerability assigned multiple CVE IDs
- **Disputes**: Vendor disagreement that the issue is a vulnerability, sometimes involving [CWE-1036](https://cwe.mitre.org/data/definitions/1036.html).
- **Invalid**: Not a security vulnerability or insufficient information
- **Withdrawn**: CVE withdrawn by the assigning CNA

It's important to note that vendors like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) and [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) are often involved in dispute resolutions.

---
## Conclusions

I've been digging into the data, and a few things jumped out. Vulnerability management isn't getting easier.

*   We are seeing consistent growth in vulnerabilities.
*   The types of vulnerabilities are shifting.
*   Exploitation is becoming more rapid.

These trends demand a proactive, data-driven approach. Waiting is no longer an option.
### Key Takeaways from 2025

1. **Volume continues to grow**: With 48,124 CVEs, 2025 set a new record in vulnerability disclosures. We're seeing no slowdown in reported issues.

2. **Severity remains concerning**: 18,958 CVEs (39.4%) were rated Critical or High severity. This high percentage demands focus on effective risk management.

3. **Common weaknesses persist**: Memory safety issues and web application vulnerabilities continue to dominate the top [CWE](https://cwe.mitre.org/) list. Expect to see continued exploitation of issues like [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting) and [CWE-416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free).

4. **Ecosystem expansion**: The growing number of CNAs reflects broader participation in coordinated vulnerability disclosure. This is a positive trend for faster identification.

5. **Data quality challenges**: While improving, a significant portion of CVEs still lack complete [CVSS](https://nvd.nist.gov/vuln-metrics/cvss), [CWE](https://cwe.mitre.org/), or [CPE](https://nvd.nist.gov/products/cpe) data. This impacts accurate risk assessment. We need better data for effective defense.

---
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

