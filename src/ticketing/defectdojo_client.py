import os
import requests
from dotenv import load_dotenv

load_dotenv()


class DefectDojoClient:

    def __init__(self):

        self.base_url = (
            os.getenv("DEFECTDOJO_URL")
            .rstrip("/")
        )

        self.token = os.getenv(
            "DEFECTDOJO_API_TOKEN"
        )

        self.headers = {
            "Authorization":
                f"Token {self.token}",
            "Content-Type":
                "application/json"
        }

        self.timeout = 20


    def _get(self, endpoint, params=None):

        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            params=params,
            timeout=self.timeout
        )

        if response.status_code != 200:

            print(
                f"GET {endpoint} failed: "
                f"{response.status_code}"
            )

            print(response.text)

            return None

        return response.json()


    def _post(self, endpoint, payload):

        response = requests.post(
            f"{self.base_url}{endpoint}",
            headers=self.headers,
            json=payload,
            timeout=self.timeout
        )

        if response.status_code not in [
            200,
            201
        ]:

            print(
                f"POST {endpoint} failed: "
                f"{response.status_code}"
            )

            print(response.text)

            return None

        return response.json()


    def get_tool_type(self, scanner_name):

        data = self._get(
            "/api/v2/tool_types/",
            {
                "name": scanner_name
            }
        )

        if not data:
            return None

        results = data.get(
            "results",
            []
        )

        for tool in results:

            if (
                tool.get(
                    "name",
                    ""
                ).lower()
                == scanner_name.lower()
            ):

                return tool["id"]

        return None

    def create_tool_type(self, scanner_name):

        payload = {
            "name": scanner_name,
            "description":
                f"{scanner_name} vulnerability scanner"
        }

        data = self._post(
            "/api/v2/tool_types/",
            payload
        )

        if not data:
            return None

        return data.get("id")

    def get_or_create_tool_type(
        self,
        scanner_name
    ):

        tool_id = self.get_tool_type(
            scanner_name
        )

        if tool_id:
            return tool_id

        return self.create_tool_type(
            scanner_name
        )


    def get_existing_test(
        self,
        title="Risk Prioritization Demo"
    ):

        data = self._get(
            "/api/v2/tests/",
            {
                "title": title
            }
        )

        if not data:
            return None

        results = data.get(
            "results",
            []
        )

        if results:
            return results[0]["id"]

        return None


    def get_product_type(
        self,
        name
    ):

        data = self._get(
            "/api/v2/product_types/",
            {
                "name": name
            }
        )

        if not data:
            return None

        results = data.get(
            "results",
            []
        )

        for product_type in results:

            if (
                product_type.get(
                    "name",
                    ""
                ).lower()
                == name.lower()
            ):

                return product_type["id"]

        return None

    def create_product_type(
        self,
        name
    ):

        data = self._post(
            "/api/v2/product_types/",
            {
                "name": name
            }
        )

        if not data:
            return None

        return data.get("id")

    def get_or_create_product_type(
        self,
        name
    ):

        product_type_id = (
            self.get_product_type(
                name
            )
        )

        if product_type_id:
            return product_type_id

        return self.create_product_type(
            name
        )


    def get_product(
        self,
        name
    ):

        data = self._get(
            "/api/v2/products/",
            {
                "name": name
            }
        )

        if not data:
            return None

        results = data.get(
            "results",
            []
        )

        for product in results:

            if (
                product.get(
                    "name",
                    ""
                ).lower()
                == name.lower()
            ):

                return product["id"]

        return None

    def create_product(
        self,
        name,
        product_type_id
    ):

        payload = {
            "name": name,
            "description":
                "Risk Prioritization Demo",
            "prod_type":
                product_type_id
        }

        data = self._post(
            "/api/v2/products/",
            payload
        )

        if not data:
            return None

        return data.get("id")

    def get_or_create_product(
        self,
        name="Risk Prioritization Demo"
    ):

        product_id = self.get_product(
            name
        )

        if product_id:
            return product_id

        product_type_id = (
            self.get_or_create_product_type(
                "Security Assessment"
            )
        )

        if not product_type_id:

            print(
                "Unable to create/find "
                "DefectDojo Product Type."
            )

            return None

        return self.create_product(
            name,
            product_type_id
        )


    def get_engagement(
        self,
        product_id,
        name
    ):

        data = self._get(
            "/api/v2/engagements/",
            {
                "name": name,
                "product": product_id
            }
        )

        if not data:
            return None

        results = data.get(
            "results",
            []
        )

        for engagement in results:

            if (
                engagement.get(
                    "name",
                    ""
                ).lower()
                == name.lower()
            ):

                return engagement["id"]

        return None

    def create_engagement(
        self,
        product_id,
        name
    ):

        payload = {
            "name": name,
            "description":
                "Automated risk prioritization assessment",
            "product": product_id,
            "target_start":
                "2026-08-17",
            "target_end":
                "2026-12-31",
            "status":
                "In Progress",
            "engagement_type":
                "CI/CD",
            "deduplication_on_engagement":
                True
        }

        data = self._post(
            "/api/v2/engagements/",
            payload
        )

        if not data:
            return None

        return data.get("id")

    def get_or_create_engagement(
        self,
        product_id
    ):

        name = (
            "Risk Prioritization Assessment"
        )

        engagement_id = (
            self.get_engagement(
                product_id,
                name
            )
        )

        if engagement_id:
            return engagement_id

        return self.create_engagement(
            product_id,
            name
        )


    def get_test_type(
        self
    ):


        data = self._get(
            "/api/v2/test_types/",
            {
                "name":
                    "Web Application Test"
            }
        )

        if not data:
            return 4

        results = data.get(
            "results",
            []
        )

        for test_type in results:

            if (
                test_type.get(
                    "name",
                    ""
                ).lower()
                ==
                "web application test"
            ):

                return test_type["id"]

        return 4


    def create_test(
        self,
        engagement_id,
        title="Risk Prioritization Demo"
    ):

        test_type_id = self.get_test_type()

        print(
            "DefectDojo Test Type:",
            test_type_id
        )

        if not test_type_id:

            print(
                "Unable to find "
                "DefectDojo Test Type."
            )

            return None

        payload = {
            "engagement":
                engagement_id,

            "title":
                title,

            "test_type":
                test_type_id,

            "target_start":
                "2026-08-17",

            "target_end":
                "2026-12-31",

            "branch_tag":
                "main"
        }

        data = self._post(
            "/api/v2/tests/",
            payload
        )

        if not data:
            return None

        return data.get("id")


    def get_or_create_test(self):

        title = (
            "Risk Prioritization Demo"
        )


        test_id = (
            self.get_existing_test(
                title
            )
        )

        if test_id:

            print(
                "Using existing "
                f"DefectDojo Test: {test_id}"
            )

            return test_id


        print(
            "Creating DefectDojo "
            "Product..."
        )

        product_id = (
            self.get_or_create_product()
        )

        if not product_id:

            print(
                "Unable to create/find "
                "DefectDojo Product."
            )

            return None

        print(
            "DefectDojo Product:",
            product_id
        )


        engagement_id = (
            self.get_or_create_engagement(
                product_id
            )
        )

        if not engagement_id:

            print(
                "Unable to create/find "
                "DefectDojo Engagement."
            )

            return None

        print(
            "DefectDojo Engagement:",
            engagement_id
        )


        test_id = self.create_test(
            engagement_id,
            title
        )

        if test_id:

            print(
                "Created DefectDojo Test:",
                test_id
            )

        return test_id


    def create_finding(
        self,
        finding
    ):

        url = (
            f"{self.base_url}"
            "/api/v2/findings/"
        )

        payload = {
            "test":
                finding["test"],

            "found_by":
                finding["found_by"],

            "url":
                finding.get(
                    "url",
                    ""
                ),

            "vulnerability_ids": (
                [
                    {
                        "vulnerability_id":
                            finding["cve"]
                    }
                ]
                if finding.get("cve")
                else []
            ),

            "cwes": (
                [
                    {
                        "cwe":
                            finding["cwe"]
                    }
                ]
                if finding.get("cwe")
                else []
            ),

            "title":
                finding["title"],

            "date":
                finding["date"],

            "cwe":
                (
                    int(
                        finding["cwe_number"]
                    )
                    if finding.get(
                        "cwe_number"
                    )
                    else None
                ),

            "epss_score":
                finding.get(
                    "epss"
                ),

            "known_exploited":
                finding.get(
                    "kev",
                    False
                ),

            "cvssv3_score":
                finding.get(
                    "cvss"
                ),

            "severity":
                finding["risk_level"],

            "numerical_severity":
                finding[
                    "numerical_severity"
                ],

            "description":
                finding[
                    "description"
                ],

            "mitigation":
                finding[
                    "mitigation"
                ],

            "impact":
                finding[
                    "impact"
                ],

            "fix_available":
                finding.get(
                    "fix_available",
                    False
                ),

            "references":
                finding.get(
                    "references",
                    ""
                ),

            "active":
                True,

            "verified":
                True,

            "false_p":
                False,

            "duplicate":
                False,

            "out_of_scope":
                False,

            "risk_accepted":
                False,

            "under_review":
                False,

            "under_defect_review":
                False,

            "is_mitigated":
                False,

            "dynamic_finding":
                True,

            "sla_expiration_date":
                finding.get(
                    "sla_expiration_date"
                ),

            "unique_id_from_tool":
                finding.get(
                    "unique_id_from_tool"
                )
        }

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=self.timeout
        )

        if response.status_code not in [
            200,
            201
        ]:

            print(
                "DefectDojo finding "
                "creation failed:"
            )

            print(
                "Status:",
                response.status_code
            )

            print(
                response.text
            )

            return None

        data = response.json()

        print(
            "DefectDojo finding created:",
            data.get("id")
        )

        return data