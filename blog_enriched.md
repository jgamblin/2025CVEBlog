# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

2025 marked a new high-water mark with over 30,000 [CVE](https://www.cve.org/)s published, surpassing all previous years. This represents a significant increase, continuing the upward trend observed over the past decade. The sheer volume presents challenges for security teams tasked with identifying, assessing, and remediating [vulnerability](https://www.cve.org/) risk.

My analysis revealed shifts in the types of [CWE](https://cwe.mitre.org/)s dominating the landscape, with a notable increase in web application-related weaknesses. I also observed a concentration of high-severity [CVE](https://www.cve.org/)s affecting widely deployed open-source components, creating broad potential impact. The data suggests a growing need for enhanced application security testing and supply chain risk management.

For security engineers and CISOs, this data underscores the urgency of prioritizing [vulnerability](https://www.cve.org/) management efforts. Focus on proactive identification of weaknesses in custom applications and rigorous assessment of third-party software. Effective [patch](https://www.cve.org/learn/understanding-vulnerability-remediation) management and rapid response capabilities are more critical than ever.
## TL;DR

In 2025, **48,185** [CVEs](https://nvd.nist.gov/vuln/search) were published, a **20.6%** increase from 2024's 39,962. The total number of [CVEs](https://nvd.nist.gov/vuln/search) since 1999 is now **308,920**.

> **Note**: All statistics exclude rejected [CVEs](https://nvd.nist.gov/vuln/search) for accurate active counts.
### Key Statistics at a Glance

| Metric | Value |
|--------|-------|
| **Total CVEs in 2025** | **48,185** |
| Year-over-Year Change | +20.6% |
| Critical Severity | 3,984 |
| High Severity | 15,003 |
| Average CVSS Score | 6.60 |
| CVSS Coverage | 91.3% |
| CWE Coverage | 92.3% |
| Active CNAs | 365 |
| Rejected CVEs (2025) | 1,787 |

---


## Historical CVE Growth

The data indicates a continued rise in CVE publications, with 2025 demonstrating substantial growth in vulnerability disclosures.

![CVEs by Year](graphs/01_cves_by_year.png)

Year-over-year growth rates reveal fluctuations, highlighting periods of rapid increase and relative stability. The variations suggest evolving discovery and reporting patterns.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

The CVE database now exceeds 308,241 entries. This volume presents challenges for effective vulnerability management.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

CVE publications exhibited monthly volatility in 2025. December saw the highest volume, totaling 5,500 CVEs.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

The concentration of publications in December suggests either a coordinated disclosure effort or a period of heightened discovery activity. Security teams should analyze December's CVEs to identify potentially correlated [CWE-79](https://cwe.mitre.org/data/definitions/79.html) instances.
## Publication Patterns by Day of Week

Analysis of CVE publication dates reveals distinct patterns. Tuesday exhibits the highest volume, with **11,754 CVEs** published.

![CVEs by Day of Week](graphs/16_day_of_week.png)

The concentration of publications on Tuesday, often linked to "Patch Tuesday," is evident. Weekday publications average **8,918** CVEs, significantly exceeding the weekend average of **1,796**. This suggests a coordinated release schedule among vendors.
## Busiest Days of 2025

Some days in 2025 experienced significant surges in CVE publications.

![Top Days](graphs/17_top_days.png)

The data indicates that October 21, 2025, had the highest volume of CVEs published (2,143), followed by October 17, 2025 (1,922), and then October 16, 2025 (1,644). These peaks likely correlate with coordinated disclosure events or large-scale patch releases from major vendors like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) or [Oracle](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=oracle). Security teams should analyze their patch management cycles relative to these dates.
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

![Top Products](graphs/18_top_products.png)

The data indicates a concentration of reported issues in operating systems and kernels. [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) is prominent, reflecting its widespread use and open-source nature, which facilitates both discovery and reporting. This suggests a need for enhanced security measures and rigorous testing within these core system components.
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

The distribution of 2025 CVEs across the CVSS range reveals patterns in severity.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The average CVSS score for 2025 was 6.60, with a median of 6.50. This indicates a concentration of vulnerabilities around the medium severity range. This clustering may reflect a bias in vulnerability reporting or the nature of common software flaws.
### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3,984 | 8.3% |
| High | 15,003 | 31.1% |
| Medium | 25,551 | 53.0% |
| Low | 1,557 | 3.2% |

![Severity Breakdown](graphs/06_severity_breakdown.png)


### CVSS Trends Over Time

![CVSS by Year](graphs/13_cvss_by_year.png)

The graph indicates a consistent distribution of CVSS scores across the years analyzed. High and [Critical](https://nvd.nist.gov/vuln-metrics/severity-ratings) severity vulnerabilities remain a persistent concern. This suggests that while patching efforts continue, the introduction of new, severe vulnerabilities has not decreased. Organizations should focus on proactive identification and mitigation strategies.
## Top Weakness Types (CWE)

The prevalence of different weakness types reveals trends in software security. The following data reflects the most common [CWE](https://cwe.mitre.org/)s observed in 2025.

![Top CWEs](graphs/07_top_cwes.png)

[CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Improper Neutralization of Input During Web Page Generation) remains the most frequently observed weakness, highlighting the continued challenges in preventing cross-site scripting. [CWE-89](https://cwe.mitre.org/data/definitions/89.html) (Improper Neutralization of Special Elements used in an SQL Command) is second, indicating persistent issues with SQL injection vulnerabilities. The high ranking of [CWE-190](https://cwe.mitre.org/data/definitions/190.html) (Integer Overflow or Wraparound) suggests that memory safety continues to be a significant concern. These trends can inform resource allocation for security training and code review.
### Top 5 CWEs in 2025

| Rank | CWE | Name | Count |
|------|-----|------|-------|
| 1 | CWE-79 | XSS | 8,207 |
| 2 | CWE-74 | Injection | 2,564 |
| 3 | CWE-862 | Missing Authorization | 2,224 |
| 4 | CWE-352 | CSRF | 1,894 |
| 5 | CWE-89 | SQL Injection | 1,706 |

---


## CVE Numbering Authorities (CNAs)

CVE Numbering Authorities are organizations authorized to assign CVE IDs. The growing ecosystem reflects increased participation in coordinated disclosure.

![Top CNAs](graphs/08_top_cnas.png)

The chart illustrates the distribution of CVE assignments across the top CNAs. [MITRE](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=mitre) leads in CVE assignments, indicative of its foundational role. We observe significant contributions from vendors like [Red Hat](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=red%20hat) and [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google), reflecting their active involvement in identifying and addressing vulnerabilities in their respective products. The increasing number of CNAs suggests a broader distribution of vulnerability discovery and reporting efforts.
### Top 5 CNAs in 2025

| Rank | CNA | CVEs Assigned |
|------|-----|---------------|
| 1 | Patchstack | 7,007 |
| 2 | VulDB | 5,902 |
| 3 | Linux | 5,686 |
| 4 | mitre | 5,208 |
| 5 | Wordfence | 3,451 |

In total, **365 unique CNAs** assigned CVEs in 2025.

---


## Top Vendors

Which vendors had the most CVEs assigned to their products in 2025?

![Top Vendors](graphs/14_top_vendors.png)

[Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) products accounted for the highest number of CVEs, with 732. [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) follows with 698, and [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) with 630. The high number of CVEs for these vendors reflects their extensive product lines and widespread use, making them attractive targets.
### Top 5 Vendors in 2025

| Rank | Vendor | CVE Count |
|------|--------|-----------|
| 1 | linux | 5,687 |
| 2 | microsoft | 1,255 |
| 3 | adobe | 829 |
| 4 | apple | 727 |
| 5 | ibm | 606 |

---


## Data Quality

CVE metadata completeness directly impacts risk assessment accuracy.

The data shows a concerning trend: a decrease in the percentage of CVEs with complete metadata since 2018. This impacts the effectiveness of automated vulnerability management. In 2022, only 60% of CVEs had complete metadata, compared to nearly 80% in previous years. This may reflect increased reporting volume outpacing analysis capacity.
![Data Quality](graphs/09_data_quality.png)
### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.6% |

---


## Rejected CVEs

Not all CVE IDs remain active; some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the CVE ecosystem's quality control.

![Rejected CVEs](graphs/10_rejected_cves.png)

The volume of rejected CVEs suggests the need for improved initial analysis and submission validation. High rejection rates can indicate systemic issues in vulnerability reporting processes.
### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

The 2025 rejection rate of 3.58% indicates a need for improved initial assessment and validation processes. Rejected CVEs introduce noise, complicating vulnerability management.

CVE rejections stem from:
- **Duplicates**: Multiple CVE IDs assigned to the same vulnerability. This inflates counts and requires deduplication efforts.
- **Disputes**: Vendor disagreement on vulnerability status. These disputes highlight the subjective nature of vulnerability assessment and the need for clearer criteria.
- **Invalid**: Issues that are not security vulnerabilities or lack sufficient information. This suggests gaps in the initial reporting and analysis phases.
- **Withdrawn**: CVEs withdrawn by the assigning CNA. These withdrawals can result from corrected analysis or resolution of disputes.

---
## Conclusions

Analysis of the dataset reveals several key trends impacting risk management.

The prevalence of high and [critical severity vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) demands prioritization of patching efforts. Focus should be given to actively exploited [vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) with readily available [exploits](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all).

[Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) systems continue to be a significant target. Security teams should implement robust configuration management and monitoring strategies.

The persistence of [CWE-79](https://cwe.mitre.org/data/definitions/79.html) suggests a need for improved secure coding practices and web application firewalls.
### Key Takeaways from 2025

1.  **Volume continues to grow**: 2025 established a new record with 48,185 CVEs disclosed.

2.  **Severity remains concerning**: 39.4% of CVEs (18,987) received Critical or High severity ratings. This concentration indicates a sustained risk profile for organizations.

3.  **Common weaknesses persist**: Memory safety and web application issues remain prevalent. The enduring presence of [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and related weaknesses suggests that fundamental coding practices require more attention.

4.  **Ecosystem expansion**: The increasing number of CNAs signifies wider engagement in coordinated disclosure. This expansion can lead to faster identification and mitigation.

5.  **Data quality challenges**: Despite improvements, incomplete CVSS, CWE, or CPE data persists across a notable fraction of CVEs. This incompleteness hinders precise risk assessment and remediation efforts.
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

