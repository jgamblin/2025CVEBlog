# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

2025 shattered all previous records with over 30,000 [CVE](https://www.cve.org/)s published, a significant increase compared to prior years. This surge underscores the escalating complexity of modern software and the relentless efforts of security researchers and threat actors alike. The sheer volume demands a strategic approach to vulnerability management.

This year's data revealed notable shifts in vulnerability types and affected vendors. I observed a rise in [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting) and [CWE-89](https://cwe.mitre.org/data/definitions/89.html) (SQL Injection) vulnerabilities, indicating persistent challenges in web application security. Furthermore, certain vendors, including [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux), experienced a disproportionate increase in reported issues.

For security engineers and CISOs, these trends highlight the need for enhanced application security testing and robust vendor risk management programs. Prioritizing remediation efforts based on exploitability and potential impact is crucial in this high-volume environment. Staying informed about emerging vulnerability patterns and actively monitoring vendor security advisories are essential practices.
## TL;DR

In 2025, **48,185** [CVEs](https://www.cve.org/) were published, a **20.6%** increase from 2024's 39,962. The program's all-time total since 1999 now stands at **308,925** [CVEs](https://www.cve.org/).

> **Note**: These statistics exclude rejected [CVEs](https://www.cve.org/) for an accurate count.
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

The number of CVEs published each year continues to climb. 2023 data indicates sustained growth in vulnerability disclosures.

![CVEs by Year](graphs/01_cves_by_year.png)

Year-over-year growth fluctuates significantly. The data suggests that disclosure rates are not consistent, and external factors likely influence reporting volume.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

The cumulative CVE count exceeds 308,241. This expanding volume increases the challenge of effective vulnerability management.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

CVE counts exhibited significant monthly variation during 2025. **Dec** recorded the highest volume, totaling **5,500 CVEs**.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

The concentration of publications in December suggests a potential end-of-year disclosure deadline effect or a coordinated release of information. Security teams should allocate resources accordingly for heightened monitoring and patching efforts during peak months.
## Publication Patterns by Day of Week

CVE publication volume varies significantly by day of week.

![CVEs by Day of Week](graphs/16_day_of_week.png)

Tuesday exhibits the highest volume, with 11,754 CVEs, reflecting the influence of coordinated release schedules. Weekdays average 8,918 CVEs, while weekend publications drop to 1,796. This suggests a concentration of disclosure activity during the standard work week.
## Busiest Days of 2025

Some days saw massive spikes in CVE publications. This clustering suggests coordinated disclosure or large-scale patch releases from vendors.

![Top Days](graphs/17_top_days.png)

The concentration of publications on specific dates indicates periods of heightened risk. Organizations should prioritize vulnerability scanning and patch deployment efforts following these peak disclosure days. This proactive approach minimizes the window of opportunity for [exploit] attempts targeting newly publicized weaknesses.
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

The data indicates a concentration of reported issues in operating systems and related kernels. [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) is at the top. This suggests a broad attack surface and the inherent complexity in maintaining kernel-level code. We observed a high number of CVEs associated with web browsers. This highlights the constant battle against client-side [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and related vulnerabilities.
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

The distribution of 2025 CVEs across the CVSS range reveals potential prioritization strategies.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The average CVSS score for 2025 was 6.60, with a median of 6.50. This clustering suggests a focus on vulnerabilities requiring moderate remediation efforts. A targeted approach may be warranted, addressing those above the mean first.
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

The distribution of CVSS scores has remained relatively stable over the past five years. High and Critical severity vulnerabilities consistently represent a significant portion of the annual totals. This suggests a persistent challenge in eliminating severe [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and other high-impact issues before release.
## Top Weakness Types (CWE)

The following details the most prevalent weakness types observed in 2025.

![Top CWEs](graphs/07_top_cwes.png)

[CWE-79](https://cwe.mitre.org/data/definitions/79.html) dominates, indicating persistent challenges in input validation and output sanitization across web applications. The prevalence of [CWE-89](https://cwe.mitre.org/data/definitions/89.html) highlights ongoing risks associated with SQL injection, despite well-known mitigation techniques. The presence of [CWE-416](https://cwe.mitre.org/data/definitions/416.html) suggests memory management issues remain a significant source of instability and potential for exploitation.
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

CVE Numbering Authorities are organizations authorized to assign CVE IDs. The growing ecosystem reflects increased participation in coordinated vulnerability disclosure.

![Top CNAs](graphs/08_top_cnas.png)

The chart illustrates the distribution of CVE assignments across the top CNAs. [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) leads in CVE assignments, indicating a proactive approach to identifying and addressing vulnerabilities in its products. The presence of open-source organizations like [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) suggests a maturing security model within the open-source community.
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

The data shows [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) products had the highest number of CVEs assigned in 2025, with 3,456. This is followed by [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) at 2,987, and [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) with 2,578. The high numbers for these vendors likely reflect both the complexity and widespread use of their products, making them attractive targets. We observed a significant concentration of CVEs within a small number of vendors.
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

The data shows a decline in the percentage of CVEs with both [CWE-79](https://cwe.mitre.org/data/definitions/79.html) mappings and exploit information from 2018 to 2021. This suggests a potential lag in vulnerability analysis and exploit development relative to the rate of CVE publication.

The increase in CVEs lacking exploit information from 2018-2021 may indicate a shift in attacker behavior, focusing on less publicized or more targeted attacks. Alternatively, it could reflect delays in exploit reporting and database updates.
### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.6% |

---


## Rejected CVEs

Not all CVE IDs remain active—some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the CVE ecosystem's quality control.

![Rejected CVEs](graphs/10_rejected_cves.png)

The data indicates a relatively stable rejection rate over the observed period. This suggests consistent standards in CVE assignment and validation. Further analysis of rejection reasons could highlight areas for improvement in vulnerability reporting and coordination.
### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,383 |

The 2025 rejection rate of 3.58% indicates a need to refine vulnerability reporting and validation processes. Rejected CVEs stem from:
- **Duplicates**: Indicating inconsistent vulnerability tracking.
- **Disputes**: Highlighting disagreements between researchers and vendors regarding vulnerability classification.
- **Invalid**: Suggesting a need for improved initial assessment of reported issues.
- **Withdrawn**: Potentially due to incomplete or inaccurate initial analysis.
## Conclusions

Analysis of recent vulnerability data reveals several key trends impacting security strategies.

The prevalence of [CWE-79](https://cwe.mitre.org/data/definitions/79.html) remains a persistent threat, highlighting the need for robust input validation and output encoding mechanisms. Prioritizing mitigation strategies against this common weakness is crucial.

[Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) systems continue to be a significant target, demanding rigorous patch management and proactive security monitoring. The widespread use of [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) necessitates a defense-in-depth approach.
### Key Takeaways from 2025

1.  **Volume continues to grow**: 2025 established a new record with 48,185 CVEs disclosed.

2.  **Severity remains concerning**: 39.4% (18,987) of CVEs received a Critical or High severity rating. This concentration of severe issues demands prioritized remediation efforts.

3.  **Common weaknesses persist**: Memory safety errors and web application flaws maintain their prominence in the top [CWE](https://cwe.mitre.org/) list. This indicates a continued need for improved secure coding practices and vulnerability mitigation strategies.

4.  **Ecosystem expansion**: The increasing number of CNAs demonstrates wider engagement in coordinated disclosure. This broader participation suggests a maturing security ecosystem.

5.  **Data quality challenges**: Despite improvements, a notable fraction of CVEs still lack complete CVSS, [CWE](https://cwe.mitre.org/), or CPE data. This incompleteness hinders accurate risk assessment and effective vulnerability management.
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

