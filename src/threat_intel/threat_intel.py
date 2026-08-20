import pandas as pd

from src.threat_intel.nvd import get_nvd_data
from src.threat_intel.epss import get_epss_batch
from src.threat_intel.kev import is_in_kev
from src.threat_intel.exploit_db import check_exploit_db


def clean_cve(cve_id):


    if cve_id is None:
        return None

    try:
        if pd.isna(cve_id):
            return None
    except Exception:
        pass

    cve_id = str(cve_id).strip().upper()

    if not cve_id:
        return None

    if cve_id in {
        "NAN",
        "NONE",
        "NULL",
        "NA",
        "N/A",
    }:
        return None

    return cve_id


def enrich_finding(cve_id):

    result = {
        "cvss": None,
        "epss": None,
        "kev": None,
        "exploit_available": None,
    }

    
    cve_id = clean_cve(cve_id)

    if cve_id is None:
        return result



    nvd_data = get_nvd_data(
        cve_id
    )

    if nvd_data:

        result["cvss"] = (
            nvd_data["cvss"]
        )


    result["kev"] = is_in_kev(
        cve_id
    )

    result["exploit_available"] = (
        check_exploit_db(cve_id)
    )

    return result


def enrich_findings(df):


    df = df.copy()


    cve_values = []

    for value in df["cve"]:

        cleaned = clean_cve(value)

        if cleaned is not None:
            cve_values.append(cleaned)


    unique_cves = list(
        dict.fromkeys(
            cve_values
        )
    )

    print(
        f"Unique CVEs to enrich: "
        f"{len(unique_cves)}"
    )


    print(
        "\nFetching EPSS scores..."
    )

    epss_cache = get_epss_batch(
        unique_cves
    )

    print(
        f"EPSS scores received: "
        f"{len(epss_cache)}"
    )



    cache = {}



    for position, cve_id in enumerate(
        unique_cves,
        start=1
    ):

        print(
            f"Enriching "
            f"{position}/{len(unique_cves)}: "
            f"{cve_id}"
        )

        
        intelligence = enrich_finding(
            cve_id
        )



        epss_data = epss_cache.get(
            cve_id
        )

        if epss_data:

            intelligence["epss"] = (
                epss_data["epss"]
            )

        cache[cve_id] = intelligence


    for index, row in df.iterrows():

        cve_id = clean_cve(
            row["cve"]
        )

        
        if cve_id is None:
            continue

        intelligence = cache.get(
            cve_id
        )

        if not intelligence:
            continue

        df.loc[
            index,
            "cvss"
        ] = intelligence["cvss"]

        df.loc[
            index,
            "epss"
        ] = intelligence["epss"]

        df.loc[
            index,
            "kev"
        ] = intelligence["kev"]

        df.loc[
            index,
            "exploit_available"
        ] = intelligence[
            "exploit_available"
        ]

    return df