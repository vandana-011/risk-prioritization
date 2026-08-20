import pandas as pd
from datetime import datetime, timedelta

from src.database.db import get_connection
from src.ticketing.defectdojo_client import DefectDojoClient


DEFAULT_TARGET_URL = "http://172.18.0.18"


SLA_DAYS = {
    "P1": 1,
    "P2": 3,
    "P3": 7,
    "P4": 30
}


def load_ticket_candidates():

    connection = get_connection()

    query = """
    SELECT
        id,
        scan_id,
        scanner,
        asset,
        endpoint,
        vulnerability,
        severity,
        confidence,
        cwe,
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
        ticket_status
    FROM findings
    WHERE scan_id = (
        SELECT MAX(id)
        FROM scan_runs
    )
    AND priority IN ('P1', 'P2')
    AND (
        ticket_id IS NULL
        OR ticket_id = ''
    )
    ORDER BY risk_score DESC
    """

    df = pd.read_sql(
        query,
        connection
    )

    connection.close()

    return df


def update_ticket_status(
    finding_ids,
    ticket_id
):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
    UPDATE findings
    SET
        ticket_id = %s,
        ticket_status = %s
    WHERE id = %s
    """

    for finding_id in finding_ids:

        cursor.execute(
            query,
            (
                str(ticket_id),
                "OPEN",
                int(finding_id)
            )
        )

    connection.commit()

    cursor.close()
    connection.close()


def clean_value(value):

    if pd.isna(value):
        return None

    return value


def get_cwe_number(cwe):

    cwe = clean_value(cwe)

    if not cwe:
        return None

    text = str(cwe)

    digits = "".join(
        character
        for character in text
        if character.isdigit()
    )

    if not digits:
        return None

    return int(digits)


def get_severity(priority):

    if priority == "P1":
        return "Critical", "S0"

    if priority == "P2":
        return "High", "S1"

    if priority == "P3":
        return "Medium", "S2"

    return "Low", "S3"


def get_target_url(row):

    endpoint = clean_value(
        row.get("endpoint")
    )

    asset = clean_value(
        row.get("asset")
    )

    # First preference: endpoint
    if endpoint:

        endpoint = str(
            endpoint
        ).strip()

        if endpoint.startswith(
            ("http://", "https://")
        ):
            return endpoint

    # Second preference: asset
    if asset:

        asset = str(
            asset
        ).strip()

        if asset.startswith(
            ("http://", "https://")
        ):
            return asset

        return f"http://{asset}"


    return DEFAULT_TARGET_URL


def main():

    print(
        "\n===== LOADING P1/P2 FINDINGS FROM MYSQL ====="
    )

    df = load_ticket_candidates()

    print(
        "P1/P2 findings from latest scan:",
        len(df)
    )

    if df.empty:

        print(
            "No new P1/P2 findings require tickets."
        )

        return

    print(
        "\n===== GROUPING UNIQUE VULNERABILITIES ====="
    )

    def grouping_key(row):

        cve = clean_value(
            row["cve"]
        )

        if cve:

            return (
                "CVE:"
                + str(cve)
                .strip()
                .upper()
            )

        vulnerability = (
            str(
                clean_value(
                    row["vulnerability"]
                )
                or "unknown"
            )
            .strip()
            .lower()
        )

        asset = (
            str(
                clean_value(
                    row["asset"]
                )
                or ""
            )
            .strip()
            .lower()
        )

        return (
            "VULN:"
            + vulnerability
            + "|ASSET:"
            + asset
        )

    df["ticket_key"] = df.apply(
        grouping_key,
        axis=1
    )

    groups = list(
        df.groupby(
            "ticket_key"
        )
    )

    print(
        "Unique ticket candidates:",
        len(groups)
    )

    print(
        "\n===== INITIALIZING DEFECTDOJO ====="
    )

    defectdojo = DefectDojoClient()

    created_tickets = 0

    for ticket_key, group in groups:


        group = group.sort_values(
            "risk_score",
            ascending=False
        )

        row = group.iloc[0]

        cve = clean_value(
            row["cve"]
        )

        vulnerability = (
            clean_value(
                row["vulnerability"]
            )
            or "Security Vulnerability"
        )

        priority = str(
            row["priority"]
        )

        scanners = sorted(
            set(
                str(scanner).strip()
                for scanner in group["scanner"]
                if pd.notna(scanner)
            )
        )

        print(
            "\n----------------------------------------"
        )

        print(
            "Vulnerability:",
            vulnerability
        )

        print(
            "CVE:",
            cve
        )

        print(
            "Detected by:",
            ", ".join(scanners)
        )

        print(
            "Risk score:",
            row["risk_score"]
        )

        print(
            "Priority:",
            priority
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
                "Skipping: no DefectDojo "
                "tool type found."
            )

            continue



        dojo_severity, numerical_severity = (
            get_severity(
                priority
            )
        )


        cwe_number = get_cwe_number(
            row["cwe"]
        )

        cwe_text = (
            f"CWE-{cwe_number}"
            if cwe_number
            else None
        )



        epss = clean_value(
            row["epss"]
        )

        cvss = clean_value(
            row["cvss"]
        )

        kev = clean_value(
            row["kev"]
        )

        exploit_available = clean_value(
            row["exploit_available"]
        )



        target_url = get_target_url(
            row
        )



        description = (
            clean_value(
                row["description"]
            )
            or ""
        )

        solution = (
            clean_value(
                row["solution"]
            )
            or ""
        )

        scanner_text = ", ".join(
            scanners
        )

        description_text = (
            f"{description}\n\n"
            f"===== RISK PRIORITIZATION =====\n"
            f"Risk Score: {row['risk_score']}\n"
            f"Priority: {priority}\n"
            f"Risk Level: {dojo_severity}\n"
            f"Detected By: {scanner_text}\n"
            f"Cross-Scanner Finding: "
            f"{len(scanners) > 1}\n"
            f"CVSS: {cvss}\n"
            f"EPSS: {epss}\n"
            f"Known Exploited: {kev}\n"
            f"Exploit Available: "
            f"{exploit_available}\n"
            f"Target: {target_url}"
        )

        references = ""

        if cve:

            references = (
                "https://nvd.nist.gov/vuln/detail/"
                + str(cve)
            )



        today = datetime.now().date()

        sla_days = SLA_DAYS.get(
            priority,
            30
        )

        sla_expiration = (
            today
            + timedelta(
                days=sla_days
            )
        )


        finding_payload = {

            "test": 2,

            "found_by": tool_ids,

            "url": target_url,

            "vulnerability_ids": (
                [
                    {
                        "vulnerability_id":
                            str(cve)
                    }
                ]
                if cve
                else []
            ),

            "cwes": (
                [
                    {
                        "cwe":
                            cwe_text
                    }
                ]
                if cwe_text
                else []
            ),

            "cve": (
                str(cve)
                if cve
                else None
            ),

            "cwe": cwe_text,

            "cwe_number":
                cwe_number,

            "title": str(
                vulnerability
            ),

            "date":
                today.strftime(
                    "%Y-%m-%d"
                ),

            "epss": epss,

            "kev":
                bool(kev)
                if kev is not None
                else False,

            "cvss": cvss,

            "risk_level":
                dojo_severity,

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

            "sla_expiration_date":
                sla_expiration.strftime(
                    "%Y-%m-%d"
                ),

            "unique_id_from_tool":
                (
                    f"{ticket_key}-"
                    f"{'-'.join(scanners)}"
                )
        }

        result = (
            defectdojo
            .create_finding(
                finding_payload
            )
        )

        if result:

            ticket_id = result.get(
                "id"
            )

            finding_ids = (
                group["id"]
                .tolist()
            )

            update_ticket_status(
                finding_ids,
                ticket_id
            )

            created_tickets += 1

            print(
                f"Ticket created: "
                f"DefectDojo #{ticket_id}"
            )

            print(
                "Linked MySQL findings:",
                len(finding_ids)
            )

            print(
                "SLA:",
                sla_expiration
            )

    print(
        "\n===== TICKETING COMPLETE ====="
    )

    print(
        "DefectDojo tickets created:",
        created_tickets
    )


if __name__ == "__main__":
    main()