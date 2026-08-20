import xml.etree.ElementTree as ET
import pandas as pd
import re


def parse_openvas_report(file_path):

    tree = ET.parse(file_path)
    root = tree.getroot()

    findings = []

    for result in root.findall(".//result"):

        if result.find("nvt") is None:
            continue

        nvt = result.find("nvt")

        name = result.findtext("name")
        host = result.findtext("host")
        port = result.findtext("port")

        severity_text = result.findtext("severity")
        threat = result.findtext("threat")
        description = result.findtext("description")

        solution = nvt.find("solution")



        result_text = ET.tostring(
            result,
            encoding="unicode"
        )

        cves = re.findall(
            r"CVE-\d{4}-\d{4,7}",
            result_text,
            re.IGNORECASE
        )


        cves = list(dict.fromkeys(
            cve.upper()
            for cve in cves
        ))



        try:
            cvss = float(severity_text)
        except (TypeError, ValueError):
            cvss = None


        qod = result.findtext("qod/value")

        try:
            confidence = int(qod)
        except (TypeError, ValueError):
            confidence = None



        if port:
            endpoint = f"{host}:{port}"
        else:
            endpoint = host



        evidence = description



        if cves:

            for cve in cves:

                findings.append({

                    "scanner": "OpenVAS",

                    "asset": host,

                    "endpoint": endpoint,

                    "method": None,

                    "parameter": None,

                    "attack": None,

                    "vulnerability": name,

                    "severity": threat,

                    "confidence": confidence,

                    "cwe": None,

                    "evidence": evidence,

                    "description": description,

                    "solution": (
                        solution.text
                        if solution is not None
                        else None
                    ),

                    "cve": cve,

                    "cvss": cvss,

                    "epss": None,

                    "kev": None,

                    "exploit_available": None
                })

        else:

        
            findings.append({

                "scanner": "OpenVAS",

                "asset": host,

                "endpoint": endpoint,

                "method": None,

                "parameter": None,

                "attack": None,

                "vulnerability": name,

                "severity": threat,

                "confidence": confidence,

                "cwe": None,

                "evidence": evidence,

                "description": description,

                "solution": (
                    solution.text
                    if solution is not None
                    else None
                ),

                "cve": None,

                "cvss": cvss,

                "epss": None,

                "kev": None,

                "exploit_available": None
            })

    return pd.DataFrame(findings)


if __name__ == "__main__":

    df = parse_openvas_report(
        "data/raw/openvas-report.xml"
    )

    print("\n===== OPENVAS FINDINGS =====")

    print("Total findings:", len(df))

    print("\n===== SAMPLE =====")

    print(
        df[
            [
                "scanner",
                "asset",
                "endpoint",
                "vulnerability",
                "severity",
                "confidence",
                "cve",
                "cvss"
            ]
        ]
        .head(10)
        .to_string(index=False)
    )

    print("\n===== CVE FINDINGS =====")

    print(
        df[
            [
                "vulnerability",
                "cve",
                "cvss"
            ]
        ]
        .dropna(subset=["cve"])
        .to_string(index=False)
    )