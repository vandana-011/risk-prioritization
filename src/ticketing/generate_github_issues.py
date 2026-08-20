import pandas as pd

from src.database.db import get_connection
from src.ticketing.github_client import GitHubClient


def load_github_candidates():

    connection = get_connection()

    try:

        query = """
        SELECT
            id,
            scan_id,
            scanner,
            detected_by,
            scanner_count,
            cross_scanner,
            asset,
            endpoint,
            vulnerability,
            severity,
            confidence,
            cwe,
            evidence,
            description,
            solution,
            cve,
            cvss,
            epss,
            kev,
            exploit_available,
            asset_criticality,
            risk_score,
            priority,
            ticket_id,
            ticket_status,
            owner_team,
            github_issue_id,
            github_issue_url
        FROM findings
        WHERE priority IN ('P1', 'P2')
        AND ticket_id IS NOT NULL
        AND ticket_id != ''
        AND (
            github_issue_id IS NULL
            OR github_issue_id = 0
        )
        """

        df = pd.read_sql(
            query,
            connection
        )

    finally:

        connection.close()

    return df


def clean(value):

    if pd.isna(value):
        return None

    return value


def yes_no(value):

    if value is None or pd.isna(value):
        return "No"

    return "Yes" if bool(value) else "No"


def get_target(row):

    endpoint = clean(
        row["endpoint"]
    )

    asset = clean(
        row["asset"]
    )

    if endpoint:

        endpoint = str(
            endpoint
        ).strip()

        if endpoint.startswith(
            ("http://", "https://")
        ):
            return endpoint

    if asset:

        asset = str(
            asset
        ).strip()

        if asset.startswith(
            ("http://", "https://")
        ):
            return asset

        return "http://" + asset

    return "http://172.18.0.18"


def get_priority_label(priority):

    return f"priority:{str(priority).lower()}"


def get_severity_label(severity):

    if not severity:
        return "severity:unknown"

    return (
        "severity:"
        + str(severity).lower()
    )


def get_display_severity(severity, cvss):

    if cvss is not None:

        try:

            score = float(cvss)

            if score >= 9.0:
                return "Critical"

            if score >= 7.0:
                return "High"

            if score >= 4.0:
                return "Medium"

            return "Low"

        except (ValueError, TypeError):
            pass

    if severity:
        return str(severity).title()

    return "Unknown"


def get_owner_label(owner_team):

    if not owner_team:
        return "owner:security"

    owner = (
        str(owner_team)
        .lower()
        .replace(" ", "-")
    )

    return f"owner:{owner}"


def build_title(row):

    priority = str(
        row["priority"]
    )

    cve = clean(
        row["cve"]
    )

    vulnerability = (
        clean(
            row["vulnerability"]
        )
        or "Security Vulnerability"
    )

    if cve:

        return (
            f"[{priority}] "
            f"{cve} - "
            f"{vulnerability}"
        )

    return (
        f"[{priority}] "
        f"{vulnerability}"
    )


def get_detected_scanners(group):

    detected_by_values = []

    if "detected_by" in group.columns:

        for detected_by in group["detected_by"]:

            if pd.notna(detected_by):

                detected_by_values.extend(
                    scanner.strip()
                    for scanner in str(
                        detected_by
                    ).split(",")
                    if scanner.strip()
                )

    if detected_by_values:

        return sorted(
            set(detected_by_values)
        )

    return sorted(
        set(
            str(scanner).strip()
            for scanner in group["scanner"]
            if pd.notna(scanner)
            and str(scanner).strip()
        )
    )


def build_body(group):

    row = group.sort_values(
        "risk_score",
        ascending=False
    ).iloc[0]

    cve = clean(
        row["cve"]
    )

    cwe = clean(
        row["cwe"]
    )

    cvss = clean(
        row["cvss"]
    )

    epss = clean(
        row["epss"]
    )

    kev = yes_no(
        row["kev"]
    )

    exploit = yes_no(
        row["exploit_available"]
    )

    risk_score = clean(
        row["risk_score"]
    )

    priority = clean(
        row["priority"]
    )

    severity = get_display_severity(
        row["severity"],
        row["cvss"]
    )

    owner_team = clean(
        row["owner_team"]
    )

    ticket_id = clean(
        row["ticket_id"]
    )

    description = (
        clean(
            row["description"]
        )
        or "No description available."
    )

    solution = (
        clean(
            row["solution"]
        )
        or "No remediation information available."
    )

    target = get_target(
        row
    )

    scanners = get_detected_scanners(
        group
    )

    scanner_text = "\n".join(
        f"- {scanner}"
        for scanner in scanners
    )

    scanner_count = clean(
        row.get("scanner_count")
    )

    if scanner_count is None:

        scanner_count = len(
            scanners
        )

    cross_scanner_value = row.get(
        "cross_scanner"
    )

    if (
        cross_scanner_value is not None
        and not pd.isna(
            cross_scanner_value
        )
    ):

        cross_scanner = yes_no(
            cross_scanner_value
        )

    else:

        cross_scanner = (
            "Yes"
            if len(scanners) > 1
            else "No"
        )

    sla = {
        "P1": "24 hours",
        "P2": "3 days",
        "P3": "7 days",
        "P4": "30 days"
    }

    sla_value = sla.get(
        priority,
        "30 days"
    )

    sla_hours = {
        "P1": 24,
        "P2": 3 * 24,
        "P3": 7 * 24,
        "P4": 30 * 24
    }

    hours = sla_hours.get(
        priority,
        30 * 24
    )

    from datetime import datetime, timedelta

    ticket_created_date = datetime(
        2026,
        8,
        16
    ).date()

    due_date = (
        ticket_created_date
        + timedelta(hours=hours)
    )

    cve_text = (
        cve
        if cve
        else "N/A"
    )

    cwe_text = (
        cwe
        if cwe
        else "N/A"
    )

    cvss_text = (
        str(cvss)
        if cvss is not None
        else "N/A"
    )

    epss_text = (
        str(epss)
        if epss is not None
        else "N/A"
    )

    return f"""
# Vulnerability Remediation

## Risk Summary

| Field | Value |
|---|---|
| Priority | **{priority}** |
| Risk Score | **{risk_score}** |
| Severity | **{severity}** |
| Owner Team | **{owner_team}** |
| SLA | **{sla_value}** |
| Due Date | **{due_date}** |

## Vulnerability

| Field | Value |
|---|---|
| CVE | {cve_text} |
| CWE | {cwe_text} |
| CVSS | {cvss_text} |
| EPSS | {epss_text} |
| Known Exploited (KEV) | {kev} |
| Exploit Available | {exploit} |

## Detection

**Detected By:**

{scanner_text}

**Scanner Count:** {scanner_count}

**Cross-Scanner Finding:** {cross_scanner}

## Affected Target

`{target}`

## Description

{description}

## Evidence

The finding was correlated from the scanner results stored in the
risk-prioritization database.

## Recommended Remediation

{solution}

## Tracking

**DefectDojo Ticket:** #{int(ticket_id)}

**MySQL Finding IDs:**

{", ".join(str(x) for x in group["id"].tolist())}

---

### Automated Risk Prioritization

This GitHub issue was automatically generated by the
Security Risk Prioritization pipeline.

The vulnerability was:

1. Parsed from security scanner reports
2. Normalized
3. Deduplicated
4. Correlated across scanners
5. Enriched with threat intelligence
6. Assigned a risk score
7. Prioritized
8. Sent to DefectDojo
9. Assigned to the responsible owner team
10. Created as a GitHub remediation issue
""".strip()


def update_github_info(
    finding_ids,
    issue_id,
    issue_url
):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    UPDATE findings
    SET
        github_issue_id = %s,
        github_issue_url = %s
    WHERE id = %s
    """

    for finding_id in finding_ids:

        cursor.execute(
            query,
            (
                issue_id,
                issue_url,
                int(finding_id)
            )
        )

    connection.commit()

    cursor.close()
    connection.close()


def main():

    print(
        "\n===== LOADING GITHUB CANDIDATES ====="
    )

    df = load_github_candidates()

    print(
        "P1/P2 findings ready for GitHub:",
        len(df)
    )

    if df.empty:

        print(
            "No new findings require GitHub issues."
        )

        return

    groups = list(
        df.groupby(
            "ticket_id"
        )
    )

    groups = sorted(
        groups,
        key=lambda item: item[1]["risk_score"].max(),
        reverse=True
    )

    print(
        "GitHub issues to create:",
        len(groups)
    )

    github = GitHubClient()

    created = 0

    for ticket_id, group in groups:

        row = group.sort_values(
            "risk_score",
            ascending=False
        ).iloc[0]

        title = build_title(
            row
        )

        body = build_body(
            group
        )

        priority = str(
            row["priority"]
        )

        severity = get_display_severity(
            row["severity"],
            row["cvss"]
        )

        owner_team = clean(
            row["owner_team"]
        )

        labels = [
            get_priority_label(
                priority
            ),
            get_severity_label(
                severity
            ),
            get_owner_label(
                owner_team
            )
        ]

        scanners = get_detected_scanners(
            group
        )

        for scanner in scanners:

            scanner_lower = (
                scanner
                .strip()
                .lower()
            )

            if scanner_lower in [
                "zap",
                "nuclei",
                "openvas"
            ]:

                labels.append(
                    f"scanner:{scanner_lower}"
                )

        if clean(row["cve"]):

            labels.append(
                "cve"
            )

        labels = list(
            dict.fromkeys(labels)
        )

        print(
            "\n----------------------------------------"
        )

        print(
            "DefectDojo ticket:",
            ticket_id
        )

        print(
            "GitHub title:",
            title
        )

        print(
            "Owner:",
            owner_team
        )

        print(
            "Detected by:",
            ", ".join(scanners)
        )

        print(
            "Scanner count:",
            len(scanners)
        )

        print(
            "Labels:",
            ", ".join(labels)
        )

        result = github.create_issue(
            title,
            body,
            labels
        )

        if result:

            issue_id = result["id"]
            issue_number = result["number"]
            issue_url = result["url"]

            update_github_info(
                group["id"].tolist(),
                issue_id,
                issue_url
            )

            created += 1

            print(
                f"GitHub Issue #{issue_number} created"
            )

            print(
                "URL:",
                issue_url
            )

    print(
        "\n===== GITHUB ISSUE GENERATION COMPLETE ====="
    )

    print(
        "Issues created:",
        created
    )


if __name__ == "__main__":
    main()