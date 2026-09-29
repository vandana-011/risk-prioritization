import pandas as pd
from datetime import date

from src.database.db import get_connection




def is_accepted_risk(row):

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT
                accepted_risk_id,
                cve,
                vulnerability,
                reason,
                accepted_by,
                start_date,
                end_date,
                status
            FROM accepted_risks
            WHERE status = 'ACTIVE'
            AND start_date <= %s
            AND end_date >= %s
            """,
            (date.today(), date.today())
        )

        accepted_risks = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()



    cve = row.get("cve")

    if not pd.isna(cve):

        cve_value = (
            str(cve)
            .strip()
            .upper()
        )

        for risk in accepted_risks:

            accepted_cve = risk.get("cve")

            if accepted_cve:

                accepted_cve_value = (
                    str(accepted_cve)
                    .strip()
                    .upper()
                )

                if cve_value == accepted_cve_value:
                    return True


    vulnerability = row.get("vulnerability")

    if not pd.isna(vulnerability):

        vulnerability_value = (
            str(vulnerability)
            .strip()
            .lower()
        )

        for risk in accepted_risks:

            accepted_vulnerability = (
                risk.get("vulnerability")
            )

            if accepted_vulnerability:

                accepted_vulnerability_value = (
                    str(accepted_vulnerability)
                    .strip()
                    .lower()
                )

                if (
                    vulnerability_value
                    == accepted_vulnerability_value
                ):
                    return True

    return False




def is_false_positive(row):

    endpoint = row.get("endpoint")
    evidence = row.get("evidence")
    description = row.get("description")


    endpoint_text = (
        ""
        if pd.isna(endpoint)
        else str(endpoint).lower()
    )

    evidence_text = (
        ""
        if pd.isna(evidence)
        else str(evidence).lower()
    )

    description_text = (
        ""
        if pd.isna(description)
        else str(description).lower()
    )

    combined_text = (
        evidence_text
        + " "
        + description_text
    )



    endpoint_missing = (
        "404" in combined_text
        or "not found" in combined_text
        or "does not exist" in combined_text
    )

    if endpoint_missing:

        return True

    return False




def classify_finding(row):

    
    if is_accepted_risk(row):

        return (
            "ACCEPTED_RISK",
            "Finding matches an active organization-approved risk exception."
        )

    
    if is_false_positive(row):

        return (
            "FALSE_POSITIVE",
            "Available evidence indicates that the reported endpoint or resource does not exist."
        )

    
    return (
        "VALID",
        "No accepted-risk exception or strong false-positive condition was identified."
    )




def apply_risk_filter(df):

    result = df.copy()

    classifications = []
    reasons = []

    for _, row in result.iterrows():

        classification, reason = (
            classify_finding(row)
        )

        classifications.append(
            classification
        )

        reasons.append(
            reason
        )

    result[
        "classification"
    ] = classifications

    result[
        "classification_reason"
    ] = reasons

    return result