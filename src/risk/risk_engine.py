import pandas as pd



def severity_to_score(severity):
    """
    Convert scanner severity into a 0-100 score.
    """

    severity_scores = {
        "Critical": 100,
        "High": 85,
        "Medium": 65,
        "Low": 35,
        "Informational": 10
    }

    if pd.isna(severity):
        return 50

    return severity_scores.get(
        str(severity).strip().title(),
        50
    )



def confidence_to_score(confidence):


    if pd.isna(confidence):
        return 50

    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        return 50

    if confidence > 4:
        return max(0, min(confidence, 100))


    confidence_scores = {
        0: 0,
        1: 25,
        2: 50,
        3: 75,
        4: 100
    }

    return confidence_scores.get(
        int(confidence),
        50
    )




def boolean_to_score(value):


    if pd.isna(value):
        return 0

    if isinstance(value, bool):
        return 100 if value else 0

    value = str(value).strip().lower()

    if value in ["true", "yes", "1"]:
        return 100

    return 0


def calculate_risk_score(row):


    confidence_score = confidence_to_score(
        row.get("confidence")
    )

    asset_criticality = row.get(
        "asset_criticality",
        3
    )

    try:
        asset_criticality = float(asset_criticality)
    except (ValueError, TypeError):
        asset_criticality = 3

    asset_criticality = max(
        1,
        min(asset_criticality, 5)
    )

    asset_score = (
        asset_criticality / 5
    ) * 100


    cve = row.get("cve")

    has_cve = (
        pd.notna(cve)
        and str(cve).strip() != ""
    )


    if has_cve:

        # CVSS
        if pd.notna(row.get("cvss")):

            try:
                cvss_score = (
                    float(row["cvss"]) / 10
                ) * 100
            except (ValueError, TypeError):
                cvss_score = severity_to_score(
                    row.get("severity")
                )

        else:

            cvss_score = severity_to_score(
                row.get("severity")
            )

        
        if pd.notna(row.get("epss")):

            try:
                epss_score = (
                    float(row["epss"]) * 100
                )
            except (ValueError, TypeError):
                epss_score = 0

        else:
            epss_score = 0

        
        kev_score = boolean_to_score(
            row.get("kev")
        )

        
        exploit_score = boolean_to_score(
            row.get("exploit_available")
        )



        risk_score = (
            cvss_score * 0.30
            + epss_score * 0.25
            + kev_score * 0.20
            + exploit_score * 0.10
            + confidence_score * 0.10
            + asset_score * 0.05
        )


    else:

        severity_score = severity_to_score(
            row.get("severity")
        )



        risk_score = (
            severity_score * 0.50
            + confidence_score * 0.20
            + asset_score * 0.30
        )

    return round(
        max(0, min(risk_score, 100)),
        2
    )



def assign_risk_level(score):
    

    if pd.isna(score):
        return None

    if score >= 90:
        return "CRITICAL"

    elif score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"



def assign_priorities(df):
    """
    Assign remediation priority based on risk score.
    """

    df["risk_level"] = df["risk_score"].apply(
        assign_risk_level
    )

    priority_map = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4"
    }

    df["priority"] = df["risk_level"].map(
        priority_map
    )

    return df



def calculate_risk(df):


    df = df.copy()


    if "asset_criticality" not in df.columns:
        df["asset_criticality"] = 3


    if "status" not in df.columns:
        df["status"] = "OPEN"

    df["status"] = (
        df["status"]
        .fillna("OPEN")
        .astype(str)
        .str.upper()
        .str.strip()
    )


    actionable_mask = (
        df["status"] != "CLOSED"
    )



    df["risk_score"] = None

    df.loc[
        actionable_mask,
        "risk_score"
    ] = df.loc[
        actionable_mask
    ].apply(
        calculate_risk_score,
        axis=1
    )



    actionable_df = df[
        actionable_mask
    ].copy()

    if not actionable_df.empty:

        actionable_df = assign_priorities(
            actionable_df
        )

        df.loc[
            actionable_df.index,
            "risk_level"
        ] = actionable_df["risk_level"]

        df.loc[
            actionable_df.index,
            "priority"
        ] = actionable_df["priority"]



    df.loc[
        ~actionable_mask,
        "risk_score"
    ] = None

    df.loc[
        ~actionable_mask,
        "risk_level"
    ] = None

    df.loc[
        ~actionable_mask,
        "priority"
    ] = None

    return df