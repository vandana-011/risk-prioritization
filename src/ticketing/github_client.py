import os
import requests
from dotenv import load_dotenv


load_dotenv()


class GitHubClient:

    def __init__(self):

        self.token = os.getenv("GITHUB_TOKEN")
        self.owner = os.getenv("GITHUB_OWNER")
        self.repo = os.getenv("GITHUB_REPO")

        if not self.token:
            raise ValueError(
                "GITHUB_TOKEN is missing from .env"
            )

        if not self.owner:
            raise ValueError(
                "GITHUB_OWNER is missing from .env"
            )

        if not self.repo:
            raise ValueError(
                "GITHUB_REPO is missing from .env"
            )

        self.base_url = (
            f"https://api.github.com/repos/"
            f"{self.owner}/{self.repo}"
        )

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    def create_issue(
        self,
        title,
        body,
        labels=None
    ):

        url = f"{self.base_url}/issues"

        payload = {
            "title": title,
            "body": body
        }

        if labels:
            payload["labels"] = labels

        response = requests.post(
            url,
            headers=self.headers,
            json=payload,
            timeout=15
        )

        if response.status_code == 201:

            data = response.json()

            return {
                "id": data["id"],
                "number": data["number"],
                "url": data["html_url"]
            }

        print(
            "GitHub issue creation failed."
        )

        print(
            "Status:",
            response.status_code
        )

        print(
            response.text
        )

        return None