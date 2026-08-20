import json
import pandas as pd


def parse_zap_report(file_path):

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    findings = []

    for site in data.get("site", []):


        site_name = (
            site.get("@name")
            or site.get("name")
            or site.get("url")
            or ""
        )

        for alert in site.get("alerts", []):

            alert_name = alert.get("alert", "")
            risk = alert.get("riskdesc", "")
            confidence = alert.get("confidence", "")
            description = alert.get("desc", "")
            solution = alert.get("solution", "")
            cwe = alert.get("cweid", "")

            for instance in alert.get("instances", []):

                
                endpoint = (
                    instance.get("uri")
                    or instance.get("url")
                    or instance.get("URI")
                    or ""
                )

                
                if not endpoint:
                    endpoint = site_name

                findings.append({
                    "scanner": "ZAP",

                    
                    "site": site_name,

                    
                    "vulnerability": alert_name,
                    "risk": risk,
                    "confidence": confidence,

                    
                    "url": endpoint,

            
                    "method": instance.get("method", ""),
                    "parameter": instance.get("param", ""),

                    
                    "attack": instance.get("attack", ""),
                    "evidence": instance.get("evidence", ""),

                    
                    "description": description,
                    "solution": solution,

                    
                    "cwe": cwe
                })

    return pd.DataFrame(findings)