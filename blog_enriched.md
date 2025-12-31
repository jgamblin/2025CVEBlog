# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

Another year, another record-breaking year for CVE disclosures. In this annual review, I analyze the [Common Vulnerabilities and Exposures](https://cve.mitre.org/) (CVE) data for 2025, examining trends in vulnerability disclosures, severity distributions, and the organizations driving vulnerability documentation. We're seeing familiar vulnerability types appear frequently.
## Executive Summary

**2025 saw 48,124 [CVEs](https://www.cve.org/) published**, an increase of **20.4%** compared to 39,962 CVEs in 2024. I'm tracking this trend closely, as it represents a significant acceleration. This brings the all-time total to **308,859 CVEs** since the program began in 1999.

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

The number of [CVE](https://www.cve.org/)s published each year continues its upward trajectory. 2025 marks another year of significant growth in vulnerability disclosures. I'm watching this trend closely.

![CVEs by Year](graphs/01_cves_by_year.png)

The growth isn't uniform—some years saw dramatic increases while others showed modest growth or even slight declines. The year-over-year growth rate provides a clearer picture of these fluctuations. We need to understand these peaks to anticipate future vulnerability surges.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

Looking at the cumulative total, we've now surpassed **308,180 CVEs** in the database. This aggregation highlights the increasing attack surface we all face.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

CVE publications saw fluctuations in 2025. I observed **Dec** as the peak month, reaching **5,439 CVEs**. This might indicate increased end-of-year reporting or a surge in discovered vulnerabilities.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

---
## CVSS Score Analysis

The [Common Vulnerability Scoring System](https://nvd.nist.gov/vuln-metrics/cvss) (CVSS) helps standardize severity assessments. I analyzed the distribution of CVSS scores for the 2025 CVEs we examined.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The **average CVSS score for 2025 was 6.60**, with a **median of 6.50**. This indicates a moderate level of severity overall, but the distribution shows a wide range. We need to dig deeper into the high and critical vulnerabilities.
### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3,980 | 8.3% |
| High | 14,978 | 31.1% |
| Medium | 25,517 | 53.0% |
| Low | 1,557 | 3.2% |

![Severity Breakdown](graphs/06_severity_breakdown.png)


### CVSS Trends Over Time

I've been tracking [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) scores over time and wanted to share some observations.

![CVSS by Year](graphs/13_cvss_by_year.png)

We can see a general trend of higher severity vulnerabilities being reported. This doesn't necessarily mean code is getting worse, but could reflect better vulnerability discovery and reporting.
---
## Top Weakness Types (CWE)

The [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) categorizes security weaknesses. I analyzed 2025 vulnerability data and these are the most prevalent weakness types:

*   [CWE-79](https://cwe.mitre.org/data/definitions/79.html) remains a top issue.
*   Improper Input Validation continues to be a significant problem.

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

CVE Numbering Authorities (CNAs) are organizations authorized to assign [CVE](https://www.cve.org/) IDs. The ecosystem continues to grow; I'm seeing more organizations participating in coordinated vulnerability disclosure. This is good.

We're tracking which CNAs are most active.

![Top CNAs](graphs/08_top_cnas.png)

This chart shows the top CNAs by CVE count. Note the high volume from vendors like [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) and [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft). They handle a large number of vulnerabilities across their product lines. Seeing increased participation from more vendors is a positive trend in vulnerability management.
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

I took a look at the [NVD](https://nvd.nist.gov/vuln/search) data and these vendors topped the list. Keep in mind that a high number of CVEs doesn't automatically mean a vendor is less secure; it can also indicate a strong commitment to vulnerability discovery and patching.

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

Not all [CVE](https://www.cve.org/) entries have complete metadata. I've noticed this impacts downstream analysis. Here's how data quality has evolved over the years:

![Data Quality](graphs/09_data_quality.png)

Incomplete data makes identifying root causes harder. For example, without proper [CWE](https://cwe.mitre.org/) mappings, fixing code becomes harder. I find myself spending more time enriching data. This directly impacts the time to remediate vulnerabilities in [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) products, for example.
### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.5% |

---


## Rejected CVEs

Not all [CVE](https://www.cve.org/) IDs remain active—some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the [CVE](https://www.cve.org/) ecosystem's quality control. I find rejected [CVE](https://www.cve.org/) analysis useful for understanding data quality.

![Rejected CVEs](graphs/10_rejected_cves.png)
### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

In 2025, we saw 1,787 [CVE](https://www.cve.org/) rejections, representing 3.58% of all CVEs issued. These rejections happen for a few key reasons:

- **Duplicates**: The same vulnerability assigned multiple CVE IDs. This often occurs with vulnerabilities affecting [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) products.
- **Disputes**: Vendor disagreement that the issue is a vulnerability. We've seen this with potential [CWE-20](https://cwe.mitre.org/data/definitions/20.html) cases.
- **Invalid**: Not a security vulnerability or insufficient information to validate. This can include issues like missing [CWE](https://cwe.mitre.org/) classification.
- **Withdrawn**: CVE withdrawn by the assigning CNA.

---
## Conclusions

I've been digging into the data, and a few things jumped out.

*   We're still seeing a high volume of vulnerabilities related to web applications. Keep those [input validation](https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/) techniques sharp.
*   Supply chain issues aren't going away. Knowing your dependencies is crucial.

Here's a quick recap of what we covered.
### Key Takeaways from 2025

1. **Volume continues to grow**: I've seen the numbers. With 48,124 CVEs, 2025 set a new record in vulnerability disclosures. Expect this trend to continue.

2. **Severity remains concerning**: 18,958 CVEs (39.4%) were rated Critical or High severity. This means nearly 40% of disclosed vulnerabilities pose a significant risk.

3. **Common weaknesses persist**: Memory safety issues and web application vulnerabilities continue to dominate the top [CWE](https://cwe.mitre.org/) list. We need to focus on preventing [CWE-119](https://cwe.mitre.org/data/definitions/119.html) and [CWE-79](https://cwe.mitre.org/data/definitions/79.html).

4. **Ecosystem expansion**: The growing number of CNAs reflects broader participation in coordinated vulnerability disclosure. More eyes on the problem are generally a good thing.

5. **Data quality challenges**: While improving, a significant portion of CVEs still lack complete [CVSS](https://nvd.nist.gov/vuln-metrics/cvss), [CWE](https://cwe.mitre.org/), or [CPE](https://nvd.nist.gov/products/cpe) data. This makes accurate risk assessment difficult.
---
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

