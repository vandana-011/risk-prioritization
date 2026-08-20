import os
import pandas as pd


INPUT_FILE = "data/threat_intel/final_prioritized_findings.csv"
OUTPUT_DIR = "data/report"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "security_risk_report.html"
)


def load_data():
    print("===== LOADING FINAL DATASET =====")

    df = pd.read_csv(INPUT_FILE)

    print("Findings:", len(df))

    return df


def calculate_summary(df):

    summary = {}

    summary["total_findings"] = len(df)

    summary["cve_findings"] = (
        df["cve"].notna().sum()
    )

    summary["cwe_findings"] = (
        df["cwe"].notna().sum()
    )

    summary["critical"] = (
        df["risk_level"]
        .eq("CRITICAL")
        .sum()
    )

    summary["high"] = (
        df["risk_level"]
        .eq("HIGH")
        .sum()
    )

    summary["medium"] = (
        df["risk_level"]
        .eq("MEDIUM")
        .sum()
    )

    summary["low"] = (
        df["risk_level"]
        .eq("LOW")
        .sum()
    )

    summary["kev"] = (
        df["kev"]
        .fillna(False)
        .eq(True)
        .sum()
    )

    summary["exploits"] = (
        df["exploit_available"]
        .fillna(False)
        .eq(True)
        .sum()
    )

    return summary


def scanner_summary(df):

    return (
        df["scanner"]
        .value_counts()
        .to_dict()
    )


def generate_top_findings(df):

    columns = [
        "rank",
        "scanner",
        "asset",
        "vulnerability",
        "cve",
        "cwe",
        "cvss",
        "epss",
        "kev",
        "exploit_available",
        "risk_score",
        "risk_level",
        "priority",
        "risk_factors",
        "recommended_action"
    ]

    available = [
        col for col in columns
        if col in df.columns
    ]

    top = (
        df.sort_values(
            "risk_score",
            ascending=False
        )
        [available]
        .head(20)
    )

    return top


def generate_html(df):

    summary = calculate_summary(df)

    scanners = scanner_summary(df)

    top_findings = generate_top_findings(df)

    scanner_rows = ""

    for scanner, count in scanners.items():

        scanner_rows += f"""
        <tr>
            <td>{scanner}</td>
            <td>{count}</td>
        </tr>
        """

    top_rows = ""

    for _, row in top_findings.iterrows():

        cve = (
            row["cve"]
            if pd.notna(row["cve"])
            else "-"
        )

        cwe = (
            row["cwe"]
            if pd.notna(row["cwe"])
            else "-"
        )

        risk_factors = (
            row["risk_factors"]
            if pd.notna(row["risk_factors"])
            else "-"
        )

        action = (
            row["recommended_action"]
            if pd.notna(row["recommended_action"])
            else "-"
        )

        top_rows += f"""
        <tr>
            <td>{row.get("rank", "-")}</td>
            <td>{row["scanner"]}</td>
            <td>{row["vulnerability"]}</td>
            <td>{cve}</td>
            <td>{cwe}</td>
            <td>{row["risk_score"]}</td>
            <td>
                <span class="badge {str(row["risk_level"]).lower()}">
                    {row["risk_level"]}
                </span>
            </td>
            <td>{row["priority"]}</td>
            <td>{risk_factors}</td>
            <td>{action}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Security Risk Prioritization Report
</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 30px;
    color: #222;
}}

.container {{
    max-width: 1500px;
    margin: auto;
}}

h1 {{
    margin-bottom: 5px;
}}

.subtitle {{
    color: #666;
    margin-bottom: 30px;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 20px;
    margin-bottom: 30px;
}}

.card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow:
        0 2px 8px rgba(0,0,0,0.08);
}}

.card-title {{
    color: #777;
    font-size: 14px;
}}

.card-value {{
    font-size: 32px;
    font-weight: bold;
    margin-top: 10px;
}}

.section {{
    background: white;
    padding: 25px;
    border-radius: 10px;
    margin-bottom: 30px;
    box-shadow:
        0 2px 8px rgba(0,0,0,0.08);
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    background: #222;
    color: white;
    padding: 10px;
    text-align: left;
}}

td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
    vertical-align: top;
}}

tr:hover {{
    background: #f5f5f5;
}}

.badge {{
    padding: 5px 10px;
    border-radius: 15px;
    font-size: 12px;
    font-weight: bold;
}}

.critical {{
    background: #ffcccc;
    color: #990000;
}}

.high {{
    background: #ffe0b3;
    color: #995c00;
}}

.medium {{
    background: #fff2b3;
    color: #806600;
}}

.low {{
    background: #d9f2d9;
    color: #267326;
}}

.summary-grid {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 15px;
}}

.summary-item {{
    padding: 15px;
    background: #f7f7f7;
    border-radius: 8px;
}}

.small {{
    font-size: 13px;
    color: #666;
}}

</style>

</head>


<body>

<div class="container">


<h1>
    Security Risk Prioritization Report
</h1>

<div class="subtitle">
Automated vulnerability correlation,
threat intelligence and risk prioritization
</div>



<div class="cards">

<div class="card">
<div class="card-title">
Total Findings
</div>

<div class="card-value">
{summary["total_findings"]}
</div>
</div>


<div class="card">
<div class="card-title">
Critical
</div>

<div class="card-value">
{summary["critical"]}
</div>
</div>


<div class="card">
<div class="card-title">
High
</div>

<div class="card-value">
{summary["high"]}
</div>
</div>


<div class="card">
<div class="card-title">
CVE Findings
</div>

<div class="card-value">
{summary["cve_findings"]}
</div>
</div>

</div>


<div class="section">

<h2>
Threat Intelligence
</h2>

<div class="summary-grid">

<div class="summary-item">
<b>Unique CVE Findings</b>

<br><br>

{summary["cve_findings"]}
</div>


<div class="summary-item">
<b>CWE Findings</b>

<br><br>

{summary["cwe_findings"]}
</div>


<div class="summary-item">
<b>CISA KEV</b>

<br><br>

{summary["kev"]}
</div>


<div class="summary-item">
<b>Public Exploits</b>

<br><br>

{summary["exploits"]}
</div>

</div>

</div>




<div class="section">

<h2>
Risk Distribution
</h2>

<table>

<tr>
<th>Risk Level</th>
<th>Findings</th>
</tr>

<tr>
<td>
<span class="badge critical">
CRITICAL
</span>
</td>

<td>
{summary["critical"]}
</td>
</tr>

<tr>
<td>
<span class="badge high">
HIGH
</span>
</td>

<td>
{summary["high"]}
</td>
</tr>

<tr>
<td>
<span class="badge medium">
MEDIUM
</span>
</td>

<td>
{summary["medium"]}
</td>
</tr>

<tr>
<td>
<span class="badge low">
LOW
</span>
</td>

<td>
{summary["low"]}
</td>
</tr>

</table>

</div>



<div class="section">

<h2>
Scanner Findings
</h2>

<table>

<tr>
<th>Scanner</th>
<th>Findings</th>
</tr>

{scanner_rows}

</table>

</div>




<div class="section">

<h2>
Top 20 Security Risks
</h2>

<p class="small">
Findings are ordered by calculated risk score.
</p>

<table>

<tr>

<th>Rank</th>
<th>Scanner</th>
<th>Vulnerability</th>
<th>CVE</th>
<th>CWE</th>
<th>Risk Score</th>
<th>Risk Level</th>
<th>Priority</th>
<th>Why?</th>
<th>Action</th>

</tr>

{top_rows}

</table>

</div>




<div class="section">

<h2>
Risk Prioritization Methodology
</h2>

<p>
The platform combines vulnerability findings from
multiple security scanners and removes exact
duplicates before prioritization.
</p>

<p>
CVE-based findings are enriched using vulnerability
and threat intelligence including CVSS, EPSS,
CISA Known Exploited Vulnerabilities and public
exploit availability.
</p>

<p>
The resulting information is combined with scanner
confidence and asset criticality to calculate a
transparent 0-100 risk score.
</p>

<p>
Findings are then assigned priorities from P1 to P4,
where P1 represents the highest remediation priority.
</p>

</div>


</div>

</body>

</html>
"""

    return html


def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    df = load_data()

    html = generate_html(df)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print()
    print("===== REPORT GENERATED =====")
    print(
        "Output:",
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()