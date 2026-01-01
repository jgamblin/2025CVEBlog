# 2025 CVE Data Review

*By Jerry Gamblin | January 01, 2026*

---

2025 set a new baseline with **48,185+ published CVEs**. While the sheer volume is climbing, the median CVSS score remained surprisingly stable. We are seeing a distinct shift toward web application flaws (specifically in the CMS ecosystem) and a wider distribution of vendors, proving that vulnerabilities are spreading deeper into the supply chain.

This massive growth is exactly why I launched RogoLabs. I am building free tools like [cve.icu](https://cve.icu) (real-time tracking), [cnascorecard.org](https://cnascorecard.org) (CNA performance), and [cveforecast.org](https://cveforecast.org) (predictive modeling) to ensure vulnerability data remains accessible and usable for the community.

The takeaway for engineers is simple: **you can't patch everything.** With volume at this level, your only move is to ruthlessly prioritize based on exploitability and automate the rest.

## TL;DR

In 2025, **48,185 CVEs** were published, a **20.6%** increase from 2024's 39,962. The total number of CVEs since 1999 now stands at **308,920**.

> **Note**: All statistics in this report exclude rejected CVEs.

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

The volume of published CVEs increased again in 2025, continuing the established upward trend.

![CVEs by Year](graphs/01_cves_by_year.png)

Year-over-year growth fluctuates, but 2025's **21% growth** is significant compared to the previous year. This indicates that despite better tooling, the rate of discovery is outpacing our ability to remediate.

![Year-over-Year Growth](graphs/02_yoy_growth.png)

The cumulative CVE count now exceeds **308,000**.

![Cumulative Growth](graphs/03_cumulative_growth.png)

---

## 2025 Monthly Distribution

The data shows a variable rate of CVE publications throughout 2025. **December** exhibited the highest volume, totaling **5,500 CVEs**. While December is traditionally quieter, 2025 saw an anomalous spike, with over 11% of the year's total vulnerabilities disclosed in the final month alone.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

---

## Publication Patterns by Day of Week

Analysis of CVE publication dates reveals distinct trends linked to vendor release cycles.

![CVEs by Day of Week](graphs/16_day_of_week.png)

**Tuesday** remains the king of disclosure, with **11,754 CVEs**, driven largely by the industry-standard "Patch Tuesday" release cadence. The drop-off is sharp: weekdays averaged 8,918 CVEs, while weekends averaged only 1,796. Security teams can generally expect the quietest period to be Sunday.

---

## Busiest Days of 2025

The data shows significant clustering of CVE publications. The top day, **February 26th**, saw nearly 800 CVEs published in a single 24-hour window. These spikes create massive "risk windows" where security teams are flooded with data.

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

Beyond vendors, specific products exhibiting the highest number of CVEs in 2025:

![Top Products](graphs/18_top_products.png)

The data reveals that the **Linux Kernel** is the single product with the most vulnerabilities (3,649). However, context is vital here: this high number reflects the transparent, open-source nature of Kernel development where *every* fix is often assigned a CVE, unlike closed-source operating systems that may bundle fixes.

### Top 5 Products

| Rank | Product | CVE Count |
|------|---------|----------|
| 1 | Linux Kernel | 3,649 |
| 2 | Windows 10 | 623 |
| 3 | Android | 509 |
| 4 | Adobe Experience Manager | 377 |
| 5 | macOS | 362 |

---

## CVSS Score Analysis

The distribution of CVEs across the CVSS range in 2025 reveals trends in vulnerability severity.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The **average CVSS score for 2025 was 6.60**, with a median of 6.50. This indicates a concentration of vulnerabilities in the medium severity range. We observed a substantial number of vulnerabilities scoring between 7.0 and 8.9, suggesting a significant attack surface requiring immediate attention.

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

---

## Top Weakness Types (CWE)

I analyzed the prevalence of weakness types based on the Common Weakness Enumeration. The data from 2025 reveals the most frequently observed [CWEs](https://cwe.mitre.org/data/index.html).

![Top CWEs](graphs/07_top_cwes.png)

**The Web Application Crisis:**
The dominance of **[CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting)** with over 8,000 entries is alarming. Despite XSS being a known issue for decades, it remains the most common vulnerability class. Combined with **[CWE-74](https://cwe.mitre.org/data/definitions/74.html) (Injection)**, **[CWE-862](https://cwe.mitre.org/data/definitions/862.html) (Missing Authorization)**, and **[CWE-89](https://cwe.mitre.org/data/definitions/89.html) (SQL Injection)**, web vulnerabilities account for a massive portion of the 2025 landscape.

### Top 5 CWEs in 2025

| Rank | CWE | Name | CVE Count |
|------|-----|------|-----------|
| 1 | CWE-79 | XSS | 8,207 |
| 2 | CWE-74 | Injection | 2,564 |
| 3 | CWE-862 | Missing Authorization | 2,224 |
| 4 | CWE-352 | CSRF | 1,894 |
| 5 | CWE-89 | SQL Injection | 1,706 |

---

## CVE Numbering Authorities (CNAs)

The CVE Numbering Authority ecosystem has shifted dramatically. In previous years, major software vendors dominated this list. In 2025, we see the **"WordPress Effect."**

![Top CNAs](graphs/08_top_cnas.png)

**Patchstack** and **Wordfence**—organizations dedicated to WordPress plugin security—are now top drivers of CVE volume. **Patchstack (#1)** alone assigned **7,007 CVEs**, vastly outnumbering traditional giants like Microsoft (#6) or Google. This reflects the intense scrutiny on the third-party plugin ecosystem.

### Top 5 CNAs in 2025

| Rank | CNA | CVE Count |
|------|-----|-----------|
| 1 | Patchstack | 7,007 |
| 2 | VulDB | 5,902 |
| 3 | Linux | 5,686 |
| 4 | MITRE | 5,208 |
| 5 | Wordfence | 3,451 |

In total, **365 unique CNAs** assigned CVEs in 2025.

---

## Top Vendors

Which vendors had the most CVEs assigned to their products in 2025?

![Top Vendors](graphs/14_top_vendors.png)

The data shows **Linux** experienced the highest number of CVEs in 2025. This volume reflects its ubiquitous use and the rigorous reporting standards of the Kernel project. Microsoft and Adobe remain in the top 5, consistent with previous years, while Code-Projects (a platform for open-source code) and Apple round out the list.

### Top 5 Vendors in 2025

| Rank | Vendor | CVE Count |
|------|--------|-----------|
| 1 | Linux | 5,687 |
| 2 | Microsoft | 1,255 |
| 3 | Adobe | 829 |
| 4 | Code-Projects | 730 |
| 5 | Apple | 727 |

---

## Data Quality

CVE records exhibit varying degrees of completeness. The 2025 data indicates trends in metadata availability.

![Data Quality](graphs/09_data_quality.png)

While CVSS and CWE coverage remains high (>90%), the lag in CPE identifiers (57.6%) is a concern for automated matching tools that rely on accurate product identifiers to alert users.

### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.6% |

---

## Rejected CVEs

Not all CVE IDs remain active. Some are rejected due to duplicates, disputes, or invalid submissions.

![Rejected CVEs](graphs/10_rejected_cves.png)

The number of rejected CVEs in 2025 remained consistent with 2024 figures, hovering around 1,787. This represents a **3.58% rejection rate**, suggesting a relatively stable signal-to-noise ratio in the ecosystem.

### 2025 Rejection Statistics

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,357 |

---

## Conclusions

In 2025, the volume of reported vulnerabilities hit an all-time high, demanding continuous vigilance.

**The "WordPress Effect"** is the most significant trend of the year. With Patchstack and Wordfence accounting for over 10,000 combined CVEs, the sheer volume of vulnerabilities has shifted from "Core OS" issues to "Third-Party Plugin" issues. For security teams, this means your threat model must aggressively account for unvetted plugins and extensions.

**Linux** remains the most reported vendor, but this is a feature of open source transparency, not necessarily insecurity. Teams should focus on hardening Linux environments and ensuring they have visibility into the specific kernel modules they are running.

Finally, the dominance of **[CWE-79 (XSS)](https://cwe.mitre.org/data/definitions/79.html)** proves that secure coding practices are still not being effectively implemented at the development stage. Regular security assessments and aggressive input validation remain critical.

### Key Takeaways from 2025

1. **Volume continues to grow**: With 48,185 CVEs, 2025 set a new record in vulnerability disclosures.
2. **CNAs have shifted**: WordPress security firms (Patchstack, Wordfence) now out-publish major tech giants like Microsoft and Google.
3. **Severity remains concerning**: 18,987 CVEs (39.4%) were rated Critical or High severity.
4. **Old bugs die hard**: XSS (CWE-79) and Injection (CWE-74) continue to dominate the weakness landscape.
5. **Data quality challenges**: While improving, a significant portion of CVEs still lack complete CPE data, complicating automated matching.

---

## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on January 01, 2026.*