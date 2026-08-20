import pandas as pd


def normalize_findings(df):

    normalized = pd.DataFrame()

    normalized["scanner"] = df.get("scanner")
    normalized["asset"] = df.get("site")
    normalized["endpoint"] = df.get("url")
    normalized["method"] = df.get("method")
    normalized["parameter"] = df.get("parameter")
    normalized["attack"] = df.get("attack")
    normalized["vulnerability"] = df.get("vulnerability")



    if "severity" in df.columns:
        normalized["severity"] = (
            df["severity"]
            .astype(str)
            .str.split()
            .str[0]
            .str.upper()
        )

    elif "risk" in df.columns:
        normalized["severity"] = (
            df["risk"]
            .astype(str)
            .str.split()
            .str[0]
            .str.upper()
        )

    else:
        normalized["severity"] = None



    normalized["confidence"] = df.get("confidence")

    if "cwe" in df.columns:
        normalized["cwe"] = (
            df["cwe"]
            .astype(str)
            .str.upper()
            .replace("NONE", None)
        )
    else:
        normalized["cwe"] = None

    normalized["evidence"] = df.get("evidence")
    normalized["description"] = df.get("description")
    normalized["solution"] = df.get("solution")



    if "cve" in df.columns:
        normalized["cve"] = (
            df["cve"]
            .astype(str)
            .str.upper()
            .replace("NONE", None)
        )
    else:
        normalized["cve"] = None

    normalized["cvss"] = df.get("cvss")
    normalized["epss"] = df.get("epss")
    normalized["kev"] = df.get("kev")
    normalized["exploit_available"] = df.get(
        "exploit_available"
    )


    normalized["status"] = "OPEN"
    normalized["reason"] = ""
    normalized["reviewer"] = ""
    normalized["review_date"] = None

    normalized["scan_id"] = None

    normalized["ticket_id"] = None
    normalized["ticket_status"] = None
    normalized["first_seen"] = None
    normalized["last_seen"] = None

    return normalized