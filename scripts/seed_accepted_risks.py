import sys
from pathlib import Path
from datetime import date

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.database.db import insert_accepted_risk
accepted_risks = [
    {
        "accepted_risk_id": "AR-001",
        "cve": None,
        "vulnerability": "Operating System (OS) End of Life (EOL) Detection",
        "reason": "The legacy operating system is required by the existing application environment and cannot be upgraded immediately.",
        "accepted_by": "Security Manager",
        "start_date": date(2026, 8, 18),
        "end_date": date(2026, 12, 31),
    },
    {
        "accepted_risk_id": "AR-002",
        "cve": None,
        "vulnerability": "PHP End of Life (EOL) Detection - Linux",
        "reason": "The application currently depends on the existing PHP version. Upgrade is planned but cannot be completed immediately.",
        "accepted_by": "Application Security Team",
        "start_date": date(2026, 8, 18),
        "end_date": date(2026, 11, 30),
    },
    {
        "accepted_risk_id": "AR-003",
        "cve": "CVE-2008-3259",
        "vulnerability": None,
        "reason": "The vulnerability is accepted temporarily due to an existing legacy system dependency.",
        "accepted_by": "Security Manager",
        "start_date": date(2026, 8, 18),
        "end_date": date(2026, 12, 31),
    },
    {
        "accepted_risk_id": "AR-004",
        "cve": "CVE-2011-4415",
        "vulnerability": None,
        "reason": "Immediate remediation is not currently possible because of legacy system constraints.",
        "accepted_by": "Security Manager",
        "start_date": date(2026, 8, 18),
        "end_date": date(2026, 12, 31),
    },
]


for risk in accepted_risks:
    try:
        insert_accepted_risk(
            accepted_risk_id=risk["accepted_risk_id"],
            cve=risk["cve"],
            vulnerability=risk["vulnerability"],
            reason=risk["reason"],
            accepted_by=risk["accepted_by"],
            start_date=risk["start_date"],
            end_date=risk["end_date"],
        )

    except Exception as e:
        print(
            f"Could not insert {risk['accepted_risk_id']}: {e}"
        )


print("Accepted risk seed completed.")