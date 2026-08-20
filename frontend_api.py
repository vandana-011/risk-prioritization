from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

from src.database.db import get_connection
from src.risk.risk_explanation import generate_ai_risk_explanation


app = FastAPI(
    title="Risk Prioritization API"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_findings():

    connection = get_connection()

    try:

        query = """
            SELECT
                id,
                scanner,
                detected_by,
                scanner_count,
                cross_scanner,
                asset,
                endpoint,
                method,
                parameter,
                attack,
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
                status,
                reason,
                reviewer,
                review_date,
                ticket_id,
                ticket_status,
                first_seen,
                last_seen,
                scan_id,
                owner_team,
                github_issue_id,
                github_issue_url,
                classification,
                classification_confidence,
                classification_reason
            FROM findings
        """

        return pd.read_sql(
            query,
            connection
        )

    finally:

        connection.close()


def load_accepted_risks():

    connection = get_connection()

    try:

        query = """
            SELECT
                id,
                accepted_risk_id,
                cve,
                vulnerability,
                reason,
                accepted_by,
                start_date,
                end_date,
                status,
                created_at
            FROM accepted_risks
            ORDER BY id
        """

        return pd.read_sql(
            query,
            connection
        )

    finally:

        connection.close()


def load_processing_metrics():

    connection = get_connection()

    try:

        query = """
            SELECT
                scan_id,
                raw_findings,
                after_deduplication,
                duplicates_removed,
                deduplication_percentage,
                after_correlation,
                false_positives,
                accepted_risks,
                actionable,
                created_at
            FROM processing_metrics
            ORDER BY id DESC
            LIMIT 1
        """

        return pd.read_sql(
            query,
            connection
        )

    finally:

        connection.close()


@app.get("/api/health")
def health():

    try:

        connection = get_connection()

        cursor = connection.cursor()

        cursor.execute(
            "SELECT DATABASE()"
        )

        database = cursor.fetchone()

        cursor.execute(
            "SELECT COUNT(*) FROM findings"
        )

        count = cursor.fetchone()

        cursor.close()
        connection.close()

        return {
            "status": "ok",
            "database": database[0],
            "findings": count[0]
        }

    except Exception as error:

        return {
            "status": "error",
            "message": str(error)
        }


@app.get("/api/findings")
def findings():

    df = load_findings()

    findings_json = df.to_json(
        orient="records",
        date_format="iso"
    )

    import json

    findings = json.loads(
        findings_json
    )

    return {
        "count": len(findings),
        "findings": findings
    }


@app.get("/api/accepted-risks")
def accepted_risks():

    df = load_accepted_risks()

    df = df.where(
        pd.notna(df),
        None
    )

    return {
        "count": len(df),
        "accepted_risks": df.to_dict(
            orient="records"
        )
    }


@app.post("/api/risk-explanation")
def risk_explanation(finding: dict):

    row = pd.Series(finding)

    explanation = generate_ai_risk_explanation(
        row
    )

    return explanation


@app.get("/api/dashboard")
def dashboard():

    df = load_findings()
    accepted_df = load_accepted_risks()
    metrics_df = load_processing_metrics()

    total = len(df)

    false_positives = int(
        (
            df["classification"]
            == "FALSE_POSITIVE"
        ).sum()
    )

    accepted_risks = int(
        (
            df["classification"]
            == "ACCEPTED_RISK"
        ).sum()
    )

    actionable = int(
        (
            ~df["classification"].isin(
                [
                    "FALSE_POSITIVE",
                    "ACCEPTED_RISK"
                ]
            )
        ).sum()
    )



    processing_metrics = {}

    if not metrics_df.empty:

        metrics = metrics_df.iloc[0]

        processing_metrics = {

            "raw_findings":
                int(
                    metrics["raw_findings"]
                ),

            "after_deduplication":
                int(
                    metrics[
                        "after_deduplication"
                    ]
                ),

            "duplicates_removed":
                int(
                    metrics[
                        "duplicates_removed"
                    ]
                ),

            "deduplication_percentage":
                float(
                    metrics[
                        "deduplication_percentage"
                    ]
                ),

            "after_correlation":
                int(
                    metrics[
                        "after_correlation"
                    ]
                ),

            "false_positives":
                int(
                    metrics[
                        "false_positives"
                    ]
                ),

            "accepted_risks":
                int(
                    metrics[
                        "accepted_risks"
                    ]
                ),

            "actionable":
                int(
                    metrics[
                        "actionable"
                    ]
                )
        }


    def get_risk_level(score):

        if pd.isna(score):

            return "UNRANKED"

        score = float(score)

        if score >= 90:

            return "CRITICAL"

        if score >= 70:

            return "HIGH"

        if score >= 40:

            return "MEDIUM"

        return "LOW"


    risk_levels = (
        df["risk_score"]
        .apply(get_risk_level)
        .value_counts()
        .to_dict()
    )


    priorities = (
        df["priority"]
        .fillna("UNASSIGNED")
        .value_counts()
        .to_dict()
    )


    scanners = (
        df["scanner"]
        .fillna("UNKNOWN")
        .value_counts()
        .to_dict()
    )


    owners = (
        df["owner_team"]
        .fillna("Unassigned")
        .value_counts()
        .to_dict()
    )


    defectdojo_tickets = int(
        df["ticket_id"]
        .notna()
        .sum()
    )


    github_issues = int(
        df["github_issue_url"]
        .notna()
        .sum()
    )


    asset_criticality = (
        df["asset_criticality"]
        .fillna(3)
        .value_counts()
        .sort_index()
        .to_dict()
    )


    cve_count = int(
        df["cve"]
        .notna()
        .sum()
    )


    kev_count = int(
        (
            df["kev"]
            == True
        ).sum()
    )


    exploit_count = int(
        (
            df["exploit_available"]
            == True
        ).sum()
    )


    accepted_df = accepted_df.where(
        pd.notna(accepted_df),
        None
    )


    accepted_risk_details = (
        accepted_df.to_dict(
            orient="records"
        )
    )


    return {

        "total": total,

        "actionable":
            actionable,

        "false_positives":
            false_positives,

        "accepted_risks":
            accepted_risks,

        "processing_metrics":
            processing_metrics,

        "risk_levels":
            risk_levels,

        "priorities":
            priorities,

        "scanners":
            scanners,

        "owners":
            owners,

        "defectdojo_tickets":
            defectdojo_tickets,

        "github_issues":
            github_issues,

        "asset_criticality":
            asset_criticality,

        "cve_count":
            cve_count,

        "kev_count":
            kev_count,

        "exploit_count":
            exploit_count,

        "accepted_risk_details":
            accepted_risk_details
    }


@app.get("/api/tickets")
def tickets():

    df = load_findings()

    ticket_df = df[
        df["ticket_id"].notna()
        |
        df["github_issue_url"].notna()
    ].copy()

    tickets_json = ticket_df.to_json(
        orient="records",
        date_format="iso"
    )

    import json

    tickets = json.loads(
        tickets_json
    )

    return {
        "count": len(tickets),
        "tickets": tickets
    }