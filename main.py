import pandas as pd
from datetime import datetime

from src.parsers.zap_parser import parse_zap_report
from src.parsers.openvas_parser import parse_openvas_report
from src.parsers.nuclei_parser import parse_nuclei_report

from src.ticketing.assign_owners import determine_owner_team
from src.ticketing.defectdojo_client import DefectDojoClient
from src.ticketing.github_client import GitHubClient

from src.ticketing.generate_github_issues import (
    clean as github_clean,
    build_title as github_build_title,
    build_body as github_build_body,
    get_priority_label,
    get_severity_label,
    get_owner_label,
    update_github_info,
)

from src.normalization.normalizer import normalize_findings
from src.deduplication.deduplicator import deduplicate_findings
from src.correlation.cross_scanner import correlate_cross_scanner
from src.threat_intel.threat_intel import enrich_findings
from src.risk.risk_engine import calculate_risk
from src.assets.asset_inventory import enrich_asset_criticality
from src.filtering.risk_filter import apply_risk_filter

from src.database.db import (
    get_connection,
    create_findings_table,
    create_scan_runs_table,
    create_scan_run,
    insert_findings,
    create_accepted_risks_table,
    create_processing_metrics_table,
    insert_processing_metrics,
)


def clean(value):
    if pd.isna(value):
        return None
    return value


def get_target(row):


    endpoint = clean(row.get("endpoint"))
    asset = clean(row.get("asset"))

    if endpoint:
        endpoint = str(endpoint).strip()

        if endpoint.startswith(
            ("http://", "https://")
        ):
            return endpoint


        if endpoint.startswith("/"):
            return (
                "http://localhost:3000"
                + endpoint
            )

    if asset:
        asset = str(asset).strip()

        if asset.startswith(
            ("http://", "https://")
        ):
            return asset


    return "http://172.18.0.18"


def get_scanners(row):
    detected_by = row.get("detected_by")

    if pd.notna(detected_by):
        scanners = [
            scanner.strip()
            for scanner in str(
                detected_by
            ).split(",")
            if scanner.strip()
        ]

        if scanners:
            return scanners

    scanner = row.get("scanner")

    if pd.notna(scanner):
        return [str(scanner).strip()]

    return []


def cwe_number_from_value(value):
    if pd.isna(value):
        return None

    digits = "".join(
        character
        for character in str(value)
        if character.isdigit()
    )

    if not digits:
        return None

    return int(digits)




print("\n===== LOADING ZAP =====")

zap_df = parse_zap_report(
    "data/raw/zap-report.json"
)

print(
    "ZAP findings:",
    len(zap_df)
)


print("\n===== LOADING NUCLEI =====")

nuclei_df = parse_nuclei_report(
    "data/raw/nuclei-report.json"
)

print(
    "Nuclei findings:",
    len(nuclei_df)
)


print("\n===== LOADING OPENVAS =====")

openvas_df = parse_openvas_report(
    "data/raw/openvas-report.xml"
)

print(
    "OpenVAS findings:",
    len(openvas_df)
)


print("\n===== COMBINING SCANNER FINDINGS =====")

combined_df = pd.concat(
    [
        zap_df,
        nuclei_df,
        openvas_df,
    ],
    ignore_index=True,
)

print(
    "Combined findings:",
    len(combined_df)
)



print("\n===== NORMALIZATION =====")

normalized_df = normalize_findings(
    combined_df
)

print(
    "Normalized findings:",
    len(normalized_df)
)




print("\n===== DEDUPLICATION =====")

deduplicated_df, duplicates = (
    deduplicate_findings(
        normalized_df
    )
)
print("DEBUG after deduplicate_findings:", len(deduplicated_df))
print("DEBUG duplicate rows:", len(duplicates))


duplicates_removed = len(duplicates)

print(
    "Before deduplication:",
    len(normalized_df)
)

print(
    "After deduplication:",
    len(deduplicated_df)
)

after_deduplication_count = len(
    deduplicated_df
)

print(
    "Duplicates removed:",
    duplicates_removed
)

if len(normalized_df) > 0:
    reduction = (
        duplicates_removed
        / len(normalized_df)
    ) * 100
else:
    reduction = 0

print(
    f"Noise reduction: "
    f"{reduction:.2f}%"
)


print(
    "\n===== CROSS-SCANNER CORRELATION ====="
)

deduplicated_df = correlate_cross_scanner(
    deduplicated_df
)
print("DEBUG after correlation:", len(deduplicated_df))

after_correlation_count = len(
    deduplicated_df
)

cross_scanner_count = (
    deduplicated_df.loc[
        deduplicated_df["cross_scanner"],
        "cve"
    ]
    .dropna()
    .astype(str)
    .str.strip()
    .str.upper()
    .nunique()
)

print(
    "Findings detected by multiple scanners:",
    cross_scanner_count
)



print("\n===== RISK FILTERING =====")

deduplicated_df = apply_risk_filter(
    deduplicated_df
)

print(
    "\nClassification summary:"
)

print(
    deduplicated_df[
        "classification"
    ].value_counts()
)

valid_df = deduplicated_df[
    ~deduplicated_df[
        "classification"
    ].isin(
        [
            "FALSE_POSITIVE",
            "ACCEPTED_RISK",
        ]
    )
].copy()

false_positive_count = (
    deduplicated_df[
        "classification"
    ] == "FALSE_POSITIVE"
).sum()

accepted_risk_count = (
    deduplicated_df[
        "classification"
    ] == "ACCEPTED_RISK"
).sum()

print(
    "\n===== FILTERING RESULT ====="
)

print(
    "Total findings:",
    len(deduplicated_df)
)

print(
    "False positives:",
    false_positive_count
)

print(
    "Accepted risks:",
    accepted_risk_count
)

print(
    "Actionable findings:",
    len(valid_df)
)






print(
    "\n===== THREAT INTELLIGENCE ====="
)

valid_df = enrich_findings(
    valid_df
)

print(
    "CVE findings:",
    valid_df[
        "cve"
    ]
    .notna()
    .sum()
)



print(
    "\n===== ASSET CRITICALITY ====="
)

valid_df = enrich_asset_criticality(
    valid_df
)



print(
    "\n===== RISK PRIORITIZATION ====="
)

valid_df = calculate_risk(
    valid_df
)


print(
    "\n===== RISK SUMMARY ====="
)

print(
    valid_df[
        "risk_level"
    ]
    .value_counts(
        dropna=False
    )
)


print(
    "\n===== PRIORITY SUMMARY ====="
)

print(
    valid_df[
        "priority"
    ]
    .value_counts(
        dropna=False
    )
)



print(
    "\n===== TOP 20 RISKS ====="
)

top_columns = [
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
    "confidence",
    "risk_score",
    "risk_level",
    "priority",
]

top_columns = [
    column
    for column in top_columns
    if column in valid_df.columns
]

top_20 = (
    valid_df
    .sort_values(
        "risk_score",
        ascending=False
    )
    .head(20)
)

print(
    top_20[
        top_columns
    ].to_string(
        index=False
    )
)



print(
    "\n===== MYSQL DATABASE ====="
)

create_findings_table()

create_scan_runs_table()

create_accepted_risks_table()

create_processing_metrics_table()

scan_id = create_scan_run(
    scanner="MULTI-SCANNER",
    target="http://localhost:3000",
    total_findings=len(
        combined_df
    ),
)

insert_processing_metrics(
    scan_id=scan_id,
    raw_findings=len(combined_df),
    after_deduplication=after_deduplication_count,
    duplicates_removed=duplicates_removed,
    deduplication_percentage=reduction,
    after_correlation=after_correlation_count,
    false_positives=int(
        false_positive_count
    ),
    accepted_risks=int(
        accepted_risk_count
    ),
    actionable=len(valid_df),
)

deduplicated_df["scan_id"] = scan_id


deduplicated_df["owner_team"] = (
    deduplicated_df.apply(
        lambda row: determine_owner_team(
            row.get("vulnerability"),
            row.get("cve"),
        ),
        axis=1,
    )
)


risk_columns = [
    "cvss",
    "epss",
    "kev",
    "exploit_available",
    "asset_criticality",
    "risk_score",
    "risk_level",
    "priority",
]

for column in risk_columns:
    if column in valid_df.columns:
        deduplicated_df.loc[
            valid_df.index,
            column,
        ] = valid_df[column]


deduplicated_df["ticket_id"] = None
deduplicated_df["ticket_status"] = None
deduplicated_df["github_issue_id"] = None
deduplicated_df["github_issue_url"] = None




print(
    "\n===== DEFECTDOJO TICKETING ====="
)

defectdojo = DefectDojoClient()

dojo_test_id = defectdojo.get_or_create_test()

if not dojo_test_id:
    print(
        "ERROR: Unable to create/find "
        "DefectDojo Test."
    )
    print(
        "Skipping DefectDojo ticket creation."
    )
    dojo_test_id = None
else:
    print(
        "DefectDojo Test ID:",
        dojo_test_id
    )

ticket_candidates = valid_df[
    valid_df[
        "priority"
    ].isin(
        [
            "P1",
            "P2",
        ]
    )
].copy()

print(
    "P1/P2 ticket candidates:",
    len(ticket_candidates)
)

ticketed_keys = set()
defectdojo_created = 0

for index, row in (
    ticket_candidates
    .sort_values(
        "risk_score",
        ascending=False
    )
    .iterrows()
):

    cve = clean(
        row.get("cve")
    )

    vulnerability = (
        clean(
            row.get("vulnerability")
        )
        or "Security Vulnerability"
    )

    if cve:
        ticket_key = (
            str(cve)
            .strip()
            .upper()
        )
    else:
        ticket_key = (
            str(vulnerability)
            .strip()
            .lower()
        )


    if ticket_key in ticketed_keys:
        continue

    ticketed_keys.add(
        ticket_key
    )

    scanners = get_scanners(
        row
    )

    tool_ids = []

    for scanner in scanners:

        tool_id = (
            defectdojo
            .get_or_create_tool_type(
                scanner
            )
        )

        if tool_id:
            tool_ids.append(
                tool_id
            )

    if not tool_ids:

        print(
            "Skipping:",
            ticket_key,
            "- no DefectDojo tool type"
        )

        continue

    risk_score = row.get(
        "risk_score"
    )

    risk_level = str(
        row.get(
            "risk_level",
            "LOW",
        )
    ).upper()

    if risk_level == "CRITICAL":
        dojo_severity = "Critical"
        numerical_severity = "S0"

    elif risk_level == "HIGH":
        dojo_severity = "High"
        numerical_severity = "S1"

    elif risk_level == "MEDIUM":
        dojo_severity = "Medium"
        numerical_severity = "S2"

    else:
        dojo_severity = "Low"
        numerical_severity = "S3"

    cwe_value = row.get(
        "cwe"
    )

    cwe_number = (
        cwe_number_from_value(
            cwe_value
        )
    )

    cve_text = (
        str(cve)
        if cve
        else None
    )

    epss = row.get(
        "epss"
    )

    if pd.isna(epss):
        epss = None

    cvss = row.get(
        "cvss"
    )

    if pd.isna(cvss):
        cvss = None

    kev = row.get(
        "kev",
        False,
    )

    if pd.isna(kev):
        kev = False

    exploit_available = row.get(
        "exploit_available"
    )

    if pd.isna(exploit_available):
        exploit_available = None

    description = row.get(
        "description",
        "",
    )

    if pd.isna(description):
        description = ""

    solution = row.get(
        "solution",
        "",
    )

    if pd.isna(solution):
        solution = ""

    target = get_target(
        row
    )

    references = ""

    if cve_text:
        references = (
            "https://nvd.nist.gov/vuln/detail/"
            + cve_text
        )

    description_text = (
        f"{description}\n\n"
        f"Risk Score: {risk_score}\n"
        f"Priority: {row.get('priority')}\n"
        f"Detected By: {', '.join(scanners)}\n"
        f"Cross-Scanner: "
        f"{row.get('cross_scanner', False)}\n"
        f"CVSS: {cvss}\n"
        f"EPSS: {epss}\n"
        f"KEV: {kev}\n"
        f"Exploit Available: "
        f"{exploit_available}"
    )

    finding_payload = {
        "test": dojo_test_id,
        "found_by": tool_ids,
        "url": target,
        "cve": cve_text,
        "cwe": (
            f"CWE-{cwe_number}"
            if cwe_number
            else None
        ),
        "cwe_number": cwe_number,
        "title": str(
            vulnerability
        ),
        "date": datetime.now().strftime(
            "%Y-%m-%d"
        ),
        "epss": epss,
        "kev": bool(
            kev
        ),
        "cvss": cvss,
        "risk_level": dojo_severity,
        "numerical_severity":
            numerical_severity,
        "description":
            description_text,
        "mitigation":
            str(solution),
        "impact":
            "Exploitation of this "
            "vulnerability may affect "
            "the security of the "
            "target asset.",
        "fix_available":
            bool(solution),
        "references":
            references,
        "unique_id_from_tool":
            (
                f"{cve_text}-"
                f"{'-'.join(scanners)}"
                if cve_text
                else
                f"{vulnerability}-"
                f"{'-'.join(scanners)}"
            ),
    }

    print(
        "\n----------------------------------------"
    )

    print(
        "Vulnerability:",
        vulnerability
    )

    print(
        "CVE:",
        cve_text
    )

    print(
        "Risk score:",
        risk_score
    )

    print(
        "Priority:",
        row.get("priority")
    )

    result = (
        defectdojo
        .create_finding(
            finding_payload
        )
    )

    if result:

        finding_id = result.get(
            "id"
        )

        deduplicated_df.loc[
            index,
            "ticket_id"
        ] = str(
            finding_id
        )

        deduplicated_df.loc[
            index,
            "ticket_status"
        ] = "OPEN"

        defectdojo_created += 1

        print(
            "DefectDojo ticket created:",
            finding_id
        )

    else:

        print(
            "DefectDojo ticket creation failed."
        )


print(
    "\nDefectDojo tickets created:",
    defectdojo_created
)




insert_findings(
    deduplicated_df
)

print(
    "Inserted findings:",
    len(deduplicated_df)
)



print(
    "\n===== GITHUB ISSUE GENERATION ====="
)

github_connection = get_connection()

github_query = """
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

github_candidates = pd.read_sql(
    github_query,
    github_connection
)

github_connection.close()

print(
    "P1/P2 findings ready for GitHub:",
    len(github_candidates)
)

github_created = 0

if not github_candidates.empty:

    # One DefectDojo ticket -> one GitHub issue.
    groups = list(
        github_candidates.groupby(
            "ticket_id"
        )
    )

    github = GitHubClient()

    for ticket_id, group in groups:

        row = (
            group
            .sort_values(
                "risk_score",
                ascending=False
            )
            .iloc[0]
        )

        title = github_build_title(
            row
        )

        body = github_build_body(
            group
        )

        priority = str(
            row["priority"]
        )

        severity = github_clean(
            row["severity"]
        )

        owner_team = github_clean(
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
            ),
        ]

        scanners = set()

        for detected_by in group["detected_by"]:
            if pd.notna(detected_by):
                for scanner in str(
                    detected_by
                    ).split(","):
                    scanner = (
                        scanner
                        .strip()
                        .lower()
                        )
                    if scanner:
                        scanners.add(scanner)

        if not scanners:
            scanners = set(
                str(scanner)
                .strip()
                .lower()
                for scanner in group["scanner"]
                if pd.notna(scanner)
                and str(scanner).strip()
                )
        for scanner in scanners:
            if scanner in [
                "zap",
                "nuclei",
                "openvas",
                ]:
                labels.append(
                    f"scanner:{scanner}"
                    )
    

        if github_clean(
            row["cve"]
        ):

            labels.append(
                "cve"
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

        result = github.create_issue(
            title,
            body,
            labels
        )

        if result:

            issue_id = result[
                "id"
            ]

            issue_number = result[
                "number"
            ]

            issue_url = result[
                "url"
            ]

            update_github_info(
                group[
                    "id"
                ].tolist(),
                issue_id,
                issue_url
            )

            github_created += 1

            print(
                f"GitHub Issue "
                f"#{issue_number} created"
            )

            print(
                "URL:",
                issue_url
            )

else:

    print(
        "No DefectDojo-backed "
        "P1/P2 findings require "
        "GitHub issues."
    )


print(
    "\n===== GITHUB ISSUE GENERATION COMPLETE ====="
)

print(
    "GitHub issues created:",
    github_created
)



print(
    "\n===== COMPLETE ====="
)

print(
    "Raw findings:",
    len(combined_df)
)

print(
    "Unique findings:",
    len(deduplicated_df)
)

print(
    "Duplicates removed:",
    duplicates_removed
)

print(
    f"Noise reduction: "
    f"{reduction:.2f}%"
)

print(
    "Cross-scanner findings:",
    cross_scanner_count
)

print(
    "False positives:",
    false_positive_count
)

print(
    "Accepted risks:",
    accepted_risk_count
)

print(
    "Actionable findings:",
    len(valid_df)
)

print("\n===== FILTERING DEBUG =====")
print("Before filtering:", len(deduplicated_df))
print("False positives:", false_positive_count)
print("Accepted risks:", accepted_risk_count)
print("Actionable:", len(valid_df))
print(
    "Classification total:",
    false_positive_count
    + accepted_risk_count
    + len(valid_df)
)
print(
    "Missing from classification:",
    len(deduplicated_df)
    - (
        false_positive_count
        + accepted_risk_count
        + len(valid_df)
    )
)

print(
    "P1/P2 actionable:",
    len(
        valid_df[
            valid_df[
                "priority"
            ].isin(
                [
                    "P1",
                    "P2",
                ]
            )
        ]
    )
)

print(
    "MySQL scan ID:",
    scan_id
)

print(
    "DefectDojo tickets created:",
    defectdojo_created
)

print(
    "GitHub issues created:",
    github_created
)
