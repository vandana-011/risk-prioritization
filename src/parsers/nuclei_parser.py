import json
import pandas as pd
from src.normalization.normalizer import normalize_findings

def parse_nuclei_report(file_path):

    findings = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            info = data.get("info", {})
            classification = info.get("classification", {})

            cve_list = classification.get("cve-id", [])
            cwe_list = classification.get("cwe-id", [])

            cve = cve_list[0] if cve_list else None
            cwe = cwe_list[0] if cwe_list else None

            findings.append({
                "scanner": "Nuclei",

                "asset": data.get("host"),

                "endpoint": data.get("matched-at")
                    or data.get("url"),

                "method": (
                    data.get("request", "")
                    .split(" ", 1)[0]
                    if data.get("request")
                    else None
                ),

                "parameter": None,

                "attack": info.get("impact"),

                "vulnerability": info.get("name"),

                "severity": info.get("severity"),

                "confidence": 100
                    if data.get("matcher-status")
                    else 0,

                "cwe": cwe,

                "evidence": (
                    data.get("request", "")
                    + "\n\n"
                    + data.get("response", "")
                ),

                "description": info.get("description"),

                "solution": info.get("remediation"),

                "cve": cve,

                "cvss": classification.get("cvss-score"),

                "epss": classification.get("epss-score"),

                "kev": (
                    "kev" in info.get("tags", [])
                    or "vkev" in info.get("tags", [])
                ),

                "exploit_available": (
                    "exploit" in info.get("tags", [])
                )
            })

    return pd.DataFrame(findings)

if __name__ == "__main__":


    df = parse_nuclei_report(
        "data/raw/nuclei-report.json"
    )

    normalized = normalize_findings(df)

    print(normalized.to_string(index=False))