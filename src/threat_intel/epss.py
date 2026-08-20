import requests


EPSS_API_URL = "https://api.first.org/data/v1/epss"


def get_epss_data(cve_id):


    if not cve_id:
        return None

    try:

        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=10
        )

        if response.status_code != 200:

            print(
                f"EPSS request failed for {cve_id}: "
                f"{response.status_code}"
            )

            return None

        data = response.json()

        results = data.get(
            "data",
            []
        )

        if not results:
            return None

        result = results[0]

        return {
            "cve": cve_id,
            "epss": float(
                result.get("epss", 0)
            )
        }

    except requests.RequestException as error:

        print(
            f"EPSS request failed for {cve_id}: "
            f"{error}"
        )

        return None


def get_epss_batch(cve_ids):


    if not cve_ids:
        return {}


    cve_ids = list({
        str(cve).strip().upper()
        for cve in cve_ids
        if cve
    })

    results = {}


    batch_size = 100

    for i in range(
        0,
        len(cve_ids),
        batch_size
    ):

        batch = cve_ids[
            i:i + batch_size
        ]

        try:

            response = requests.get(
                EPSS_API_URL,
                params={
                    "cve": ",".join(batch)
                },
                timeout=20
            )

            if response.status_code != 200:

                print(
                    "EPSS batch request failed: "
                    f"{response.status_code}"
                )

                continue

            data = response.json()

            for item in data.get(
                "data",
                []
            ):

                cve = item.get(
                    "cve"
                )

                if not cve:
                    continue

                results[
                    cve.upper()
                ] = {
                    "cve": cve.upper(),
                    "epss": float(
                        item.get(
                            "epss",
                            0
                        )
                    )
                }

        except requests.RequestException as error:

            print(
                f"EPSS batch request failed: "
                f"{error}"
            )

    return results