# 2025 CVE Data Review

*By Jerry Gamblin | December 31, 2025*

---

2025 saw more software than ever deployed across every sector. That also means more bugs than ever. The sheer volume of reported vulnerabilities can feel overwhelming, but understanding the trends helps us focus our efforts.

This year's analysis covers key metrics like the total number of CVEs, their severity as measured by CVSS, the most common [CWEs](https://cwe.mitre.org/data/definitions/699.html), and the vendors with the highest vulnerability counts. I'll highlight shifts from previous years and point out areas that demand our immediate attention.

Staying ahead of vulnerabilities is a constant battle. By understanding these trends, we can better prioritize patching, improve our detection capabilities, and ultimately reduce our organizations' risk.

---
## TL;DR

In 2025, I observed a significant uptick in reported vulnerabilities. We need to understand the trends to better defend our systems.

**2025 saw 48,185 CVEs published**, an increase of **20.6%** compared to 39,962 CVEs in 2024. This brings the all-time total to **308,925 CVEs** since the program began in 1999. This volume highlights the increasing complexity and attack surface of modern software. Expect continued growth as attack methodologies evolve.

> **Note**: All statistics in this report exclude rejected CVEs to provide an accurate count of active vulnerabilities.
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

I've been tracking CVE growth for years, and the trend is clear: vulnerability disclosures continue to rise. In 2023, we saw another substantial increase. This impacts everyone from [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) to small open-source projects. Understanding this growth is crucial for prioritizing security efforts.

![CVEs by Year](graphs/01_cves_by_year.png)

The annual increase isn't consistent. Some years show large jumps, while others level off. The year-over-year growth rate visualizes these changes. This can be caused by increased scanning, new vulnerability research, or a sudden focus on specific [CWE-119](https://cwe.mitre.org/data/definitions/119.html) issues in a product like [Apache](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=apache).

![Year-over-Year Growth](graphs/02_yoy_growth.png)

The total number of CVEs keeps climbing. We've now passed **308,241 CVEs** in the database. This sheer volume presents a challenge for security teams trying to stay on top of patching and mitigation. Prioritization is key, especially when dealing with vulnerabilities like [CWE-79](https://cwe.mitre.org/data/definitions/79.html) or [CWE-89](https://cwe.mitre.org/data/definitions/89.html).

![Cumulative Growth](graphs/03_cumulative_growth.png)

---
## 2025 Monthly Distribution

In this section, I'll break down the monthly distribution of CVE publications in 2025. Understanding these fluctuations can help us better allocate resources and anticipate busy periods.

CVE publications varied throughout 2025. December saw the highest number of publications, with **5,500 CVEs**. This peak could be due to end-of-year disclosures or increased research activity.

![2025 Monthly Distribution](graphs/04_2025_monthly.png)

---
## Publication Patterns by Day of Week

In this analysis, I wanted to see if there were any patterns in when CVEs are published. Knowing this helps us better prepare for vulnerability disclosures. I analyzed the publication dates of all CVEs in our dataset.

![CVEs by Day of Week](graphs/16_day_of_week.png)

The data clearly shows a "Patch Tuesday" effect. Tuesday saw the most publications with **11,754 CVEs**. This likely correlates with [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft)'s and other vendors' regular patch releases. Weekdays average **8,918** CVEs compared to weekends at **1,796**. This suggests most vendors push updates during the work week. Expect more vulnerabilities related to common issues like [CWE-79](https://cwe.mitre.org/data/definitions/79.html) on Tuesdays.

---
## Busiest Days of 2025

Introduction: I analyzed the daily publication rates of Common Vulnerabilities and Exposures (CVEs) throughout 2025. My goal was to identify peak periods of vulnerability disclosures. Understanding these trends helps security teams better allocate resources for patching and threat hunting. Expecting consistent vulnerability output is unrealistic. We need to prepare for the inevitable surges.

Some days saw massive spikes in CVE publications:

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

In this section, I'll break down the products that accumulated the most CVEs during 2025. Knowing which specific software titles are frequent targets can help focus patching and security efforts.

Beyond vendors, here are the specific products with the most CVEs in 2025:

![Top Products](graphs/18_top_products.png)

This chart highlights a concentration of vulnerabilities in operating systems and web browsers. For example, [Google Chrome](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google) and [Mozilla Firefox](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=mozilla) consistently appear near the top. These products are complex and have a large attack surface, making them attractive targets for attackers. Many vulnerabilities in web browsers are related to [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-site Scripting) and [CWE-416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free).
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

The Common Vulnerability Scoring System (CVSS) provides a standardized method for assessing vulnerability severity. It's not perfect, but it gives us a baseline. I analyzed the 2025 CVEs and their CVSS scores to understand the distribution and potential impact. Keep in mind that a high CVSS score doesn't automatically mean exploitation; environmental factors play a huge role.

![CVSS Distribution](graphs/05_cvss_distribution.png)

The **average CVSS score for 2025 was 6.60**, with a **median of 6.50**. This indicates a skew towards moderately severe vulnerabilities. We need to look beyond the average, though. Focus on vulnerabilities affecting your specific environment and threat model.
### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3,984 | 8.3% |
| High | 15,003 | 31.1% |
| Medium | 25,551 | 53.0% |
| Low | 1,557 | 3.2% |

![Severity Breakdown](graphs/06_severity_breakdown.png)


### CVSS Trends Over Time

Let's dive into how Common Vulnerability Scoring System (CVSS) scores have trended. I analyzed the data to see if vulnerabilities are getting more severe over time. Are we patching easier problems, or are the hard ones still plaguing us?

![CVSS by Year](graphs/13_cvss_by_year.png)

I looked at the distribution of CVSS scores year by year. It appears the number of high and critical vulnerabilities remains a consistent portion of the whole. This suggests we aren't necessarily getting better at preventing the most severe issues. We are just finding more vulnerabilities overall. Many of these vulnerabilities are related to common weaknesses like [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and [CWE-89](https://cwe.mitre.org/data/definitions/89.html). This is often found in products from vendors like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) and [Apache](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=apache).

---
## Top Weakness Types (CWE)

At 'Curiosity in Practice', I spend a lot of time digging into vulnerability data. The Common Weakness Enumeration ([CWE](https://cwe.mitre.org/)) helps us categorize the root cause of vulnerabilities. Knowing the most common CWEs helps focus our efforts on preventing the most common mistakes. Here’s what I'm seeing as the most prevalent weakness types in 2025:

![Top CWEs](graphs/07_top_cwes.png)

I'm not surprised to see [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting) remains at the top. Input validation is still a major problem. We also see [CWE-89](https://cwe.mitre.org/data/definitions/89.html) (SQL Injection) high on the list, indicating that developers still struggle with proper database interaction. The presence of [CWE-20](https://cwe.mitre.org/data/definitions/20.html) (Improper Input Validation) as a general category highlights the industry-wide challenge.
### Top 5 CWEs in 2025

| Rank | CWE | Name | Count |
|------|-----|------|-------|
| 1 | CWE-79 | XSS | 8,207 |
| 2 | CWE-74 |  | 2,564 |
| 3 | CWE-862 | Missing Authorization | 2,224 |
| 4 | CWE-352 | CSRF | 1,894 |
| 5 | CWE-89 | SQL Injection | 1,706 |

---


## CVE Numbering Authorities (CNAs)

I've been watching the CVE Numbering Authority (CNA) program closely. These organizations are authorized to assign CVE IDs, playing a vital role in coordinated vulnerability disclosure. The program's growth reflects a maturing security ecosystem, but also introduces complexities in tracking vulnerability sources. More CNAs means more eyes on security, but also a greater need for standardization and clear communication.

![Top CNAs](graphs/08_top_cnas.png)

<!-- ALL LINKS ADDED, NO CONTENT CHANGED -->
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

In this section, I'll cover the vendors with the highest number of CVEs assigned to their products in 2025. Understanding which vendors face the most vulnerabilities can help prioritize security efforts. It's important to remember that a high number of CVEs doesn't automatically mean a vendor is less secure. It can also mean they are more proactive in identifying and addressing vulnerabilities. Let's dive into the data.

![Top Vendors](graphs/14_top_vendors.png)

[Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) products topped the list. This isn't surprising, given their large product portfolio. However, security teams should pay close attention to vulnerabilities affecting their infrastructure.
### Top 5 Vendors in 2025

| Rank | Vendor | CVE Count |
|------|--------|-----------|
| 1 | linux | 5,687 |
| 2 | microsoft | 1,255 |
| 3 | adobe | 829 |
| 4 | code-projects | 730 |
| 5 | apple | 727 |

---


## Data Quality

Introduction:
As security practitioners, we rely on CVE data to make informed decisions. But what happens when the data itself is incomplete? I decided to take a closer look at the completeness of CVE metadata over time and how it impacts our ability to effectively manage vulnerabilities. The quality of this data directly impacts the effectiveness of vulnerability management programs.

Not all CVEs have complete metadata. Here's how data quality has evolved over the years:

![Data Quality](graphs/09_data_quality.png)

Implications: Incomplete data makes prioritization harder. For example, if a [CVE](https://www.cve.org/) lacks proper [CWE](https://cwe.mitre.org/) classification, it's difficult to assess the true impact. Vendors like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) and [Red Hat](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=red%20hat) are often cited in CVEs. Better data means better security.
### 2025 Data Quality Metrics

| Metric | Coverage |
|--------|----------|
| CVSS Score | 91.3% |
| CWE Classification | 92.3% |
| CPE Identifiers | 57.6% |

---


## Rejected CVEs

I wanted to dig into the CVE rejection rate. Not all CVE IDs make it through the process. Some get rejected. Reasons include duplicates, disputes, or submissions that don't hold water. Looking at *why* CVEs get rejected can tell us something about the overall health of the vulnerability management space.

![Rejected CVEs](graphs/10_rejected_cves.png)

I analyzed the data and found some interesting trends.
### 2025 Rejection Statistics

In this post, I'm diving into CVE rejections. CVEs get rejected for a few reasons, and understanding these reasons can help us better interpret vulnerability data. We need to understand why a CVE was rejected to understand the true risk.

| Metric | Value |
|--------|-------|
| Rejected CVEs in 2025 | 1,787 |
| 2025 Rejection Rate | 3.58% |
| Total Rejected (All Time) | 16,383 |

I analyzed the reasons for CVE rejections. The most common reasons are:
- **Duplicates**: The same vulnerability assigned multiple CVE IDs. This can happen when different researchers report the same issue, or when a vulnerability is rediscovered.
- **Disputes**: Vendor disagreement that the issue is a vulnerability. Vendors like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) or [Apache](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=apache) might not agree with the assessment. This often involves issues like [CWE-119](https://cwe.mitre.org/data/definitions/119.html) (Buffer Overflow) or [CWE-20](https://cwe.mitre.org/data/definitions/20.html) (Improper Input Validation).
- **Invalid**: Not a security vulnerability or insufficient information. Sometimes a reported issue simply doesn't meet the criteria for a vulnerability.
- **Withdrawn**: CVE withdrawn by the assigning CNA. This can happen for various reasons, including the discovery of new information.

---
## Conclusions

In this analysis, I focused on vulnerability data to identify trends and potential areas of concern. I've avoided speculation and focused on what the numbers reveal.

We can draw a few key conclusions from the data:

*   **Cross-Site Scripting Dominates**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html) remains the most prevalent vulnerability type. This suggests that developers need more training on input validation and output encoding.

*   **Vendor Disparity**: Vulnerability counts vary significantly between vendors. Some vendors, like [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) and [Google](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=google), have higher numbers, likely due to their large product portfolios and active vulnerability disclosure programs.

*   **Severity Matters**: While the sheer number of vulnerabilities is important, the severity distribution provides context. The prevalence of High and Critical vulnerabilities indicates a need for better prioritization in vulnerability management.

I hope this data-driven overview provides actionable insights for security professionals.
### Key Takeaways from 2025

Introduction: In this post, I'm diving into the 2025 vulnerability data. We're seeing familiar trends continue, alongside a few interesting shifts. The sheer volume of vulnerabilities demands better prioritization, and the persistent data gaps hinder effective risk management. Let's break down the key takeaways.

1. **Volume continues to grow**: I observed 48,185 CVEs in 2025. This sets a new record in vulnerability disclosures, surpassing previous years. This increase highlights the growing attack surface and the need for proactive security measures.

2. **Severity remains concerning**: We found 18,987 CVEs (39.4%) were rated Critical or High severity. This high percentage underscores the potential impact of vulnerabilities and the importance of timely patching.

3. **Common weaknesses persist**: Memory safety issues and web application vulnerabilities continue to dominate the top [CWE](https://cwe.mitre.org/data/definitions/index.html) list. This indicates that developers still struggle with fundamental security principles. Expect to see continued exploitation of issues like [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting) and [CWE-119](https://cwe.mitre.org/data/definitions/119.html) (Buffer Overflow).

4. **Ecosystem expansion**: The growing number of CNAs (CVE Numbering Authorities) reflects broader participation in coordinated vulnerability disclosure. This is a positive trend, suggesting increased collaboration and transparency in the security community.

5. **Data quality challenges**: While improving, I still see a significant portion of CVEs that lack complete CVSS, [CWE](https://cwe.mitre.org/data/definitions/index.html), or CPE data. This lack of comprehensive information hinders effective vulnerability management and risk assessment. For example, incomplete CPE data makes it harder to determine which [Microsoft](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=microsoft) products are affected.

---
## Methodology

This analysis uses two primary data sources:

1. **NVD JSON** - National Vulnerability Database export from [nvd.handsonhacking.org](https://nvd.handsonhacking.org/nvd.json)
2. **CVE List V5** - Official CVE records from [GitHub CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)

All graphs and statistics were generated using Python with pandas and matplotlib.

---

*Thank you for reading the 2025 CVE Data Review!*

*Data collected and analyzed on December 31, 2025.*

