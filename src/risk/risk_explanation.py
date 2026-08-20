import os
import json
import pandas as pd
from groq import Groq


def generate_risk_factors(row):

    factors = []

    if pd.notna(row.get("cvss")):

        try:
            cvss = float(row["cvss"])

            if cvss >= 9.0:
                factors.append(
                    f"Critical CVSS score ({cvss})"
                )

            elif cvss >= 7.0:
                factors.append(
                    f"High CVSS score ({cvss})"
                )

        except (ValueError, TypeError):
            pass


    if pd.notna(row.get("epss")):

        try:
            epss = float(row["epss"])

            if epss >= 0.90:
                factors.append(
                    f"Very high exploitation probability "
                    f"({epss * 100:.2f}%)"
                )

            elif epss >= 0.50:
                factors.append(
                    f"High exploitation probability "
                    f"({epss * 100:.2f}%)"
                )

        except (ValueError, TypeError):
            pass


    kev = row.get("kev")

    if kev is True or str(kev).lower() == "true":

        factors.append(
            "Listed in CISA Known Exploited Vulnerabilities"
        )


    exploit_available = row.get(
        "exploit_available"
    )

    if (
        exploit_available is True
        or str(exploit_available).lower() == "true"
    ):

        factors.append(
            "Public exploit available"
        )


    if pd.notna(row.get("confidence")):

        try:

            confidence = float(
                row["confidence"]
            )

            if confidence >= 90:

                factors.append(
                    f"High scanner confidence "
                    f"({confidence:.0f}%)"
                )

        except (ValueError, TypeError):
            pass



    cross_scanner = row.get(
        "cross_scanner"
    )

    if (
        cross_scanner is True
        or str(cross_scanner).lower() == "true"
    ):

        detected_by = row.get(
            "detected_by"
        )

        if pd.notna(detected_by):

            factors.append(
                f"Detected by multiple security scanners "
                f"({detected_by})"
            )

        else:

            factors.append(
                "Detected by multiple security scanners"
            )


    return "; ".join(factors)


def generate_priority_reason(row):

    priority = row.get("priority")

    if priority == "P1":

        return (
            "Immediate remediation required because "
            "this is a critical-risk vulnerability with "
            "strong exploitation indicators."
        )

    elif priority == "P2":

        return (
            "High-priority remediation recommended because "
            "the finding presents significant security risk."
        )

    elif priority == "P3":

        return (
            "Medium-priority remediation recommended. "
            "Address during the planned remediation cycle."
        )

    elif priority == "P4":

        return (
            "Lower-priority finding. "
            "Address during routine security maintenance."
        )

    return "No priority assigned."


def generate_recommended_action(row):

    priority = row.get("priority")

    if priority == "P1":

        return "Remediate immediately"

    elif priority == "P2":

        return "Remediate as soon as possible"

    elif priority == "P3":

        return "Schedule remediation"

    elif priority == "P4":

        return "Address during routine maintenance"

    return "Review finding"


def generate_remediation(row):

    solution = row.get("solution")

    if pd.notna(solution):

        solution = str(solution).strip()

        if solution:

            return solution

    return (
        "Review the vulnerability details and apply "
        "the vendor-recommended security patch or mitigation."
    )


def generate_ai_risk_explanation(row):

    api_key = os.getenv(
        "GROQ_API_KEY"
    )



    if not api_key:

        return {

            "why_it_is_risk":
                "AI explanation unavailable because "
                "GROQ_API_KEY is not configured.",

            "potential_impact":
                "Review the vulnerability description "
                "and available evidence.",

            "why_this_priority":
                generate_priority_reason(row),

            "mitigation":
                generate_remediation(row),

            "recommended_action":
                generate_recommended_action(row)
        }


    client = Groq(
        api_key=api_key
    )



    data = {

        "vulnerability":
            row.get("vulnerability"),

        "cve":
            row.get("cve"),

        "cwe":
            row.get("cwe"),

        "severity":
            row.get("severity"),

        "cvss":
            row.get("cvss"),

        "epss":
            row.get("epss"),

        "kev":
            row.get("kev"),

        "exploit_available":
            row.get("exploit_available"),

        "confidence":
            row.get("confidence"),

        "asset":
            row.get("asset"),

        "endpoint":
            row.get("endpoint"),

        "asset_criticality":
            row.get("asset_criticality"),

        "risk_score":
            row.get("risk_score"),

        "priority":
            row.get("priority"),

        "evidence":
            row.get("evidence"),

        "description":
            row.get("description"),

        "solution":
            row.get("solution"),

        
        "detected_by":
            row.get("detected_by"),

        "scanner_count":
            row.get("scanner_count"),

        "cross_scanner":
            row.get("cross_scanner")
    }


    prompt = f"""
You are a cybersecurity risk analyst.

Analyze the following vulnerability finding.

The provided risk score and priority are authoritative.
Do NOT calculate, modify, or change the risk score or priority.

Explain the existing risk in clear language suitable
for a security analyst.

Return ONLY a JSON object with exactly these five fields:

why_it_is_risk
potential_impact
why_this_priority
mitigation
recommended_action

Finding:

{json.dumps(
    data,
    default=str,
    indent=2
)}

Requirements:

why_it_is_risk:
Explain why this vulnerability represents a security
risk using the supplied vulnerability information,
evidence and security indicators.

potential_impact:
Explain what an attacker could potentially achieve
if the vulnerability is exploited.

why_this_priority:
Explain why the EXISTING priority was assigned.
Use the supplied CVSS, EPSS, KEV, exploit availability,
asset criticality, confidence and risk score where available.

mitigation:
Give practical remediation or mitigation steps based
on the supplied vulnerability information and solution.

recommended_action:
Give a concise action for the security team.

If cross_scanner is true, mention that the finding was
detected by multiple scanners and use detected_by when
explaining why this increases confidence.

Do not invent CVEs, scores, exploits, affected components,
scanner results or facts that are not supported by the
supplied information.
"""


    try:

        response = client.chat.completions.create(

            model="openai/gpt-oss-120b",

            messages=[

                {
                    "role": "system",

                    "content":
                        "You are a cybersecurity risk "
                        "analysis assistant. "
                        "Return only a JSON object."
                },

                {
                    "role": "user",
                    "content": prompt
                }
            ],

            temperature=0.2,

            max_tokens=800,

            response_format={
                "type": "json_object"
            }
        )


        content = (
            response
            .choices[0]
            .message
            .content
            .strip()
        )



        result = json.loads(
            content
        )


        return {

            "why_it_is_risk":
                result.get(
                    "why_it_is_risk",
                    generate_risk_factors(row)
                ),

            "potential_impact":
                result.get(
                    "potential_impact",
                    "Review the vulnerability description "
                    "and available evidence."
                ),

            "why_this_priority":
                result.get(
                    "why_this_priority",
                    generate_priority_reason(row)
                ),

            "mitigation":
                result.get(
                    "mitigation",
                    generate_remediation(row)
                ),

            "recommended_action":
                result.get(
                    "recommended_action",
                    generate_recommended_action(row)
                )
        }


    except Exception as error:

        print(
            "===== GROQ AI EXPLANATION ERROR ====="
        )

        print(
            type(error).__name__
        )

        print(
            str(error)
        )




        return {

            "why_it_is_risk":
                generate_risk_factors(row),

            "potential_impact":
                (
                    "Review the vulnerability description "
                    "and available evidence to determine "
                    "potential impact."
                ),

            "why_this_priority":
                generate_priority_reason(row),

            "mitigation":
                generate_remediation(row),

            "recommended_action":
                generate_recommended_action(row)
        }


def add_risk_explanations(df):

    df = df.copy()


    df["risk_factors"] = df.apply(
        generate_risk_factors,
        axis=1
    )


    df["priority_reason"] = df.apply(
        generate_priority_reason,
        axis=1
    )


    df["recommended_action"] = df.apply(
        generate_recommended_action,
        axis=1
    )


    df["remediation"] = df.apply(
        generate_remediation,
        axis=1
    )


    ai_results = []


    for _, row in df.iterrows():

        ai_results.append(
            generate_ai_risk_explanation(
                row
            )
        )


    df["ai_why_it_is_risk"] = [

        result["why_it_is_risk"]

        for result in ai_results

    ]


    df["ai_potential_impact"] = [

        result["potential_impact"]

        for result in ai_results

    ]


    df["ai_why_this_priority"] = [

        result["why_this_priority"]

        for result in ai_results

    ]


    df["ai_mitigation"] = [

        result["mitigation"]

        for result in ai_results

    ]


    df["ai_recommended_action"] = [

        result["recommended_action"]

        for result in ai_results

    ]


    return df