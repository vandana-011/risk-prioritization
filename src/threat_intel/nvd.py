import os
import json
import time
import requests


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

CACHE_FILE = "data/threat_intel/nvd_cache.json"

NVD_API_KEY = os.getenv("NVD_API_KEY")


def load_cache():

    if not os.path.exists(CACHE_FILE):
        return {}

    try:

        with open(
            CACHE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception:

        return {}


def save_cache(cache):

    os.makedirs(
        os.path.dirname(CACHE_FILE),
        exist_ok=True
    )

    with open(
        CACHE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            cache,
            file,
            indent=4
        )


def get_nvd_data(cve_id):

    if not cve_id:
        return None

    cve_id = (
        str(cve_id)
        .strip()
        .upper()
    )


    cache = load_cache()

    if cve_id in cache:

        print(
            f"NVD cache hit: {cve_id}"
        )

        return cache[cve_id]



    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "cveId": cve_id
    }


    time.sleep(6)

    try:

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=15
        )

        if response.status_code == 429:

            print(
                f"NVD rate limit reached for "
                f"{cve_id}"
            )

            return None

        if response.status_code != 200:

            print(
                f"NVD request failed for "
                f"{cve_id}: "
                f"{response.status_code}"
            )

            return None

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        if not vulnerabilities:

            result = {
                "cve": cve_id,
                "cvss": None
            }

            cache[cve_id] = result
            save_cache(cache)

            return result

        cve_data = vulnerabilities[0].get(
            "cve",
            {}
        )

        metrics = cve_data.get(
            "metrics",
            {}
        )

        cvss_score = None



        if metrics.get("cvssMetricV31"):

            cvss_score = (
                metrics["cvssMetricV31"][0]
                .get("cvssData", {})
                .get("baseScore")
            )


        elif metrics.get("cvssMetricV30"):

            cvss_score = (
                metrics["cvssMetricV30"][0]
                .get("cvssData", {})
                .get("baseScore")
            )



        elif metrics.get("cvssMetricV2"):

            cvss_score = (
                metrics["cvssMetricV2"][0]
                .get("cvssData", {})
                .get("baseScore")
            )

        result = {
            "cve": cve_id,
            "cvss": cvss_score
        }



        cache[cve_id] = result

        save_cache(cache)

        return result

    except requests.RequestException as error:

        print(
            f"NVD request failed for "
            f"{cve_id}: {error}"
        )

        return None


def enrich_with_nvd(df):

    for index, row in df.iterrows():

        cve_id = row["cve"]

        if not cve_id:
            continue

        nvd_data = get_nvd_data(
            cve_id
        )

        if nvd_data:

            df.loc[
                index,
                "cvss"
            ] = nvd_data["cvss"]

    return df