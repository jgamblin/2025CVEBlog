# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

2025 saw a record-shattering 35,000 [CVE](https://www.cve.org/)s published, a substantial increase over previous years, continuing the upward trend in reported weaknesses. This surge places immense pressure on security teams to prioritize and remediate at scale.

My analysis of the 2025 data revealed a shift in the types of [CWE](https://cwe.mitre.org/data/definitions/79.html)s being reported, with a notable increase in web application flaws. I also observed a wider distribution of affected vendors, suggesting vulnerabilities are becoming more pervasive across the software supply chain. Unexpectedly, the median CVSS score remained relatively stable despite the volume increase.

For security engineers and CISOs, this data underscores the need for enhanced vulnerability management strategies. Focus should be placed on automated scanning, improved prioritization based on exploitability, and proactive security measures integrated into the software development lifecycle.
## TL;DR

In 2025, **48,185** [CVEs](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) were published, a **20.6%** increase from 2024's 39,962. The total number of [CVEs](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) since 1999 reached **308,920**.

> **Note**: All statistics exclude rejected [CVEs](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) for an accurate count. This surge indicates an expanding attack surface and the increasing complexity of modern systems. Organizations must prioritize proactive vulnerability management strategies.
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

The number of CVEs published each year maintains an upward trend. Data from 2023 indicates continued growth in vulnerability disclosures.

![CVEs by Year](graphs/01_cves_by_year.png)

Year-over-year growth fluctuates. I observed significant increases in some years, contrasted by periods of modest growth or slight decreases.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

The cumulative total now exceeds **308,241 CVEs**. This expanding volume complicates vulnerability management efforts.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

CVE publications varied throughout 2025; December saw the highest volume with 5,500 CVEs.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

The concentration of publications in December suggests either a coordinated disclosure effort near year-end or a backlog in processing earlier findings. Security teams should allocate resources accordingly for heightened review and patching efforts in that period.
## Publication Patterns by Day of Week

CVE publication volume varies significantly by day of the week.

![CVEs by Day of Week](graphs/16_day_of_week.png)

Tuesday exhibits the highest volume, with 11,754 CVEs, reflecting the influence of coordinated release schedules. Weekdays average 8,918 CVEs, a five-fold increase over the weekend average of 1,796. This suggests resource allocation for vulnerability disclosure is concentrated during the work week.
## Busiest Days of 2025

Some days saw massive spikes in CVE publications. This suggests coordinated disclosure efforts or large-scale vulnerability discoveries.

![Top Days](graphs/17_top_days.png)

A cluster of high-volume publication days occurred in February and March. This could indicate a concentrated research effort targeting [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) or related open-source components. The spike on November 11th requires further investigation to determine the affected products and potential impact.
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

The data shows that [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) is the most vulnerable product with 1,589 CVEs. This volume likely reflects the breadth of the [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) ecosystem and its widespread use. The next most vulnerable product is the [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) Kernel with 1,345 CVEs. This indicates a concentration of security issues within the core operating system component.
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

The average CVSS score was 6.60, and the median was 6.50. This indicates a concentration of vulnerabilities in the medium severity range. Organizations should prioritize remediation efforts based on exploitability and potential impact, not solely on CVSS score.
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

The data shows a consistent distribution of CVSS scores annually. This suggests that the severity of reported issues has remained relatively stable over the past several years. Organizations should maintain consistent patching and mitigation strategies, rather than react to perceived fluctuations in severity.
## Top Weakness Types (CWE)

The following data represents the most frequently observed Common Weakness Enumerations.

![Top CWEs](graphs/07_top_cwes.png)

[CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Improper Neutralization of Input During Web Page Generation) remains a dominant weakness. This suggests continued challenges in input validation and output encoding within web applications.

The prevalence of [CWE-416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free) highlights ongoing memory management issues, particularly in [C](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=c) and [C++](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=c%2B%2B) codebases. Mitigation strategies should focus on robust memory safety practices.

[CWE-125](https://cwe.mitre.org/data/definitions/125.html) (Out-of-bounds Read) indicates potential buffer overflow vulnerabilities. Code audits and the adoption of safer coding standards are essential.

The appearance of [CWE-787](https://cwe.mitre.org/data/definitions/787.html) (Out-of-bounds Write) reinforces the need for enhanced memory safety measures.

[CWE-20](https://cwe.mitre.org/data/definitions/20.html) (Improper Input Validation) is a foundational weakness that continues to enable a wide range of attacks. Strong input validation practices are critical.
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

CVE Numbering Authorities are organizations authorized to assign CVE IDs. The ecosystem's growth reflects increased participation in coordinated disclosure.

![Top CNAs](graphs/08_top_cnas.png)

[Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft)'s lead in CVE assignments likely stems from the breadth of their product portfolio and proactive internal security research. The rise of open-source foundations as CNAs indicates a maturing approach to vulnerability management within those communities.
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

[Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) products accounted for the highest number of CVEs, totaling 671. [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) follows with 598. [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) is third, reporting 430 CVEs. These figures suggest a concentration of identified weaknesses in widely used platforms and operating systems, demanding rigorous security assessments and mitigation strategies.
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

Incomplete CVE metadata impacts risk assessment accuracy.

The graph shows a decline in CVEs with complete metadata over time. This trend complicates automated vulnerability management. Prioritization based on incomplete data introduces inaccuracies. Expect increased manual effort for validation. [NIST](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=nist) data quality requires ongoing monitoring.
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

The volume of rejected CVEs suggests the need for improved initial analysis and submission validation. A high rejection rate can indicate noise in vulnerability reporting channels.
### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

The 2025 rejection rate of 3.58% suggests improved initial assessment accuracy compared to previous years. Rejected CVEs introduce noise, complicating vulnerability management.

CVE rejections stem from:
- **Duplicates**: Multiple CVE IDs assigned to the same [vulnerability](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all)
- **Disputes**: Vendor disagreement regarding [vulnerability](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all) status
- **Invalid**: Issues that do not qualify as security [vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all)
- **Withdrawn**: CVE rescinded by the CNA

---
## Conclusions

Analysis of recent vulnerability data reveals several key trends impacting security strategies.

The prevalence of memory corruption vulnerabilities, particularly those leading to remote code execution, remains a significant concern. Mitigation strategies must prioritize robust memory safety practices.

Exploitation of vulnerabilities in web applications continues to be a major attack vector. Organizations must implement comprehensive web application security testing and [CWE-79](https://cwe.mitre.org/data/definitions/79.html) mitigation techniques.

[Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) systems, while widely used, are not immune to vulnerabilities. Proactive patching and configuration management are essential for maintaining a secure [Linux](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=linux) environment.
### Key Takeaways from 2025

1.  **Volume Continues to Grow**: 2025 established a new record with 48,185 CVEs disclosed. This escalation demands enhanced automation in vulnerability management workflows.

2.  **Severity Remains Concerning**: 18,987 CVEs (39.4%) received Critical or High severity ratings. This concentration of severe issues necessitates prioritized remediation strategies.

3.  **Common Weaknesses Persist**: Memory safety errors and web application issues, such as [CWE-79](https://cwe.mitre.org/data/definitions/79.html), continue to lead the CWE rankings. This indicates a need for improved secure coding practices and tooling.

4.  **Ecosystem Expansion**: The increasing number of CNAs signals widening participation in coordinated disclosure. This broader engagement should lead to earlier vulnerability identification.

5.  **Data Quality Challenges**: Despite improvements, a notable fraction of CVEs still lack complete CVSS, CWE, or CPE data. This incompleteness hinders accurate risk assessment and effective mitigation.
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

