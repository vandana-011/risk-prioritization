import requests


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


_KEV_CACHE = None


def load_kev_catalog():


    global _KEV_CACHE

    if _KEV_CACHE is not None:
        return _KEV_CACHE

    try:

        response = requests.get(
            KEV_URL,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        _KEV_CACHE = {
            vulnerability.get("cveID", "").upper()
            for vulnerability in vulnerabilities
            if vulnerability.get("cveID")
        }

        print(
            f"KEV catalog loaded: "
            f"{len(_KEV_CACHE)} CVEs"
        )

        return _KEV_CACHE

    except requests.RequestException as error:

        print(
            f"KEV request failed: {error}"
        )

        _KEV_CACHE = set()

        return _KEV_CACHE


def is_in_kev(cve_id):


    if not cve_id:
        return False

    cve_id = str(cve_id).strip().upper()

    kev_cves = load_kev_catalog()

    return cve_id in kev_cves