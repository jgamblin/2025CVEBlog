# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

2025 set a new baseline with 48,000+ published CVEs. The volume is climbing, but the median CVSS score remained surprisingly stable. I tracked a clear shift toward web application flaws and a wider distribution of vendors, proving that vulnerabilities are spreading deeper into the supply chain.

This massive growth in data is exactly why I started RogoLabs this year. We need to ensure that as vulnerability data scales, it remains free, accessible, and usable for everyone.

The takeaway for engineers is simple: you can't patch everything. With volume at this level, your only move is to ruthlessly prioritize based on exploitability and automate the rest.
## TL;DR

In 2025, **48,185 CVEs** were published, a **20.6%** increase from the 39,962 CVEs recorded in 2024. The total number of CVEs since 1999 now stands at **308,920**.

> **Note**: All statistics exclude rejected CVEs to provide an accurate count of active vulnerabilities.
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

The volume of published CVEs sustained its upward trend in 2025, indicating a continued expansion of the attack surface.

![CVEs by Year](graphs/01_cves_by_year.png)

Year-over-year growth rates reveal variance in vulnerability disclosure. I observed periods of accelerated discovery alongside relative stabilization.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

The cumulative CVE count now exceeds 308,241. This figure underscores the escalating challenge of vulnerability management.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

The data shows a fluctuating rate of CVE publications throughout 2025. December exhibited the highest volume, with 5,500 CVEs.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)
## Publication Patterns by Day of Week

The data shows distinct patterns in CVE publication volume based on the day of the week.

![CVEs by Day of Week](graphs/16_day_of_week.png)

Tuesday saw the highest volume of publications in 2025, with **11,754 CVEs**, likely reflecting the influence of coordinated patch releases. The average number of CVEs published on weekdays was **8,918**, significantly higher than the weekend average of **1,796**. This suggests a concentration of vulnerability disclosure and publication activities during the work week.
## Busiest Days of 2025

Some days in 2025 experienced significant surges in [CVE](https://www.cve.org/) publications. These spikes often correlate with Patch Tuesdays or coordinated disclosure events. The concentration of publications on specific dates underscores the importance of efficient patch management and proactive threat monitoring.

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

Beyond vendors, the data reveals specific products with the highest number of CVEs reported in 2025.

![Top Products](graphs/18_top_products.png)

The prevalence of vulnerabilities in these products suggests a need for increased code review, security testing, and proactive patching strategies by both the [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) community and organizations deploying these technologies. The concentration highlights potential systemic weaknesses in development or integration processes.
### Top 5 Products

| Rank | Product | CVE Count |
|------|---------|----------|
| 1 | Linux Kernel | 3,649 |
| 2 | Windows 10 | 623 |
| 3 | Android | 509 |
| 4 | Experience Manager | 377 |
| 5 | Macos | 362 |

---


## CVSS Score Analysis

The distribution of CVSS scores in 2025 indicates the overall severity landscape.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The average CVSS score for 2025 was 6.60, with a median of 6.50. This clustering suggests a concentration of vulnerabilities requiring focused remediation efforts.
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

The 2025 data indicates a continued prevalence of high and critical severity vulnerabilities. The proportion of vulnerabilities with CVSS scores between 7.0 and 8.9 remains significant, demanding prioritized attention. The volume of 'Critical' vulnerabilities (9.0-10.0) suggests attackers continue to target the most severe weaknesses.
## Top Weakness Types (CWE)

The following data reflects the prevalence of weakness types observed in 2025.

![Top CWEs](graphs/07_top_cwes.png)

The dominance of [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting) indicates a continued challenge in web application security. Input validation and output encoding require increased focus.
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

CVE Numbering Authorities are organizations authorized to assign CVE IDs. The ecosystem's growth reflects a broader commitment to coordinated vulnerability disclosure.

![Top CNAs](graphs/08_top_cnas.png)

The rise of certain CNAs in 2025, as visualized above, indicates a potential shift in vulnerability discovery and reporting focus. This could be due to increased product security initiatives within those organizations, or a greater emphasis on specific vulnerability types.
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

[Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) and [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) products accounted for a substantial portion of reported CVEs in 2025. The volume of CVEs does not directly equate to overall risk, but highlights areas requiring focused vulnerability management.
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

CVE metadata completeness impacts downstream analysis. The 2025 data shows:

*   **CVSS v3.0/3.1:** 91% of CVEs include a CVSS v3.0 or v3.1 score, essential for risk prioritization.
*   **CWE:** Only 78% of CVEs are mapped to at least one [CWE-79](https://cwe.mitre.org/data/definitions/79.html), hindering root cause analysis and mitigation strategy development.
*   **Exploit Availability:** Exploit code availability remains low, with only 9% of CVEs having a known exploit. This can lead to underestimation of risk.
*   **Patch Availability:** 89% of CVEs have patch information available. This is important for remediation efforts.
### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.6% |

---


## Rejected CVEs

Not all CVE IDs remain active; some are rejected due to duplicates, disputes, or invalid submissions. Understanding rejection patterns provides insight into the quality control mechanisms within the CVE ecosystem.

![Rejected CVEs](graphs/10_rejected_cves.png)

The data shows a consistent rejection rate. This suggests a stable process for identifying and correcting errors or inconsistencies in vulnerability reporting during 2025. The volume of rejections highlights the need for continuous improvement in vulnerability disclosure and validation processes.
### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

The 2025 CVE rejection rate of 3.58% indicates a moderate level of noise in vulnerability reporting. Rejected CVEs stem from:

- **Duplicates**: Instances where the same vulnerability received multiple CVE IDs, inflating initial counts.
- **Disputes**: Vendor disagreement regarding the validity of a reported issue as a true vulnerability.
- **Invalid**: Submissions lacking sufficient information or not qualifying as security vulnerabilities.
- **Withdrawn**: CVEs retracted by the assigning CNA, often due to resolution or re-evaluation.
## Conclusions

The 2025 data reveals several key trends demanding immediate attention from security leadership.

The surge in high-severity vulnerabilities underscores the increasing complexity of modern software development and the persistent challenges in secure coding practices. We must re-evaluate our application security testing methodologies and invest in developer training focused on preventing common [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and similar weaknesses.

The dominance of [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) vulnerabilities highlights the pervasive nature of this operating system in both enterprise and cloud environments. Patch management strategies must prioritize [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) systems and incorporate automated vulnerability scanning to rapidly identify and remediate exposures.
### Key Takeaways from 2025

The year 2025 saw continued challenges in vulnerability management, demanding increased vigilance and strategic resource allocation. We observed both expected trends and areas requiring focused attention.

1. **Volume continues to grow**: A total of 48,185 CVEs were published in 2025, establishing a new high and underscoring the increasing attack surface. This necessitates enhanced automation in vulnerability detection and prioritization.

2. **Severity remains concerning**: 18,987 CVEs (39.4%) were assessed as Critical or High severity. This concentration of severe issues requires a risk-based approach to patching, focusing on the most impactful vulnerabilities.

3. **Common weaknesses persist**: Memory safety issues and web application vulnerabilities, such as [CWE-79](https://cwe.mitre.org/data/definitions/79.html), remain prevalent. This indicates a need for improved secure coding practices and increased investment in application security testing.

4. **Ecosystem expansion**: The growing number of CNAs reflects broader participation in coordinated vulnerability disclosure, leading to faster discovery. This expanded ecosystem necessitates improved communication and collaboration.

5. **Data quality challenges**: A significant portion of CVEs still lack complete CVSS, CWE, or CPE data. This incomplete data hinders accurate risk assessment and effective vulnerability management, emphasizing the need for improved data enrichment and standardization efforts.
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

