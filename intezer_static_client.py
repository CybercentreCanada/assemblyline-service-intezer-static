from requests import post, session
from typing import Dict


class IntezerStaticClient:
    def __init__(self, apikey: str = "") -> None:
        self.apikey: str = apikey
        self.headers: Dict[str, str] = {"api_key": self.apikey}
        self.base_url: str = "https://analyze.intezer.com/api/v2-0"
        self.create_session()

    def create_session(self) -> None:
        response = post(f"{self.base_url}/get-access-token", json=self.headers)
        self.session = session()
        self.session.headers["Authorization"] = f"Bearer {response.json()['result']}"

    def get_hash_results(self, sha256: str) -> None:
        response = self.session.get(f"{self.base_url}/files/{sha256}")

        if response.status_code == 200:
            return response.json()["result"]

    def get_sub_analysis(self, analysis_id: str) -> None:
        response = self.session.get(
            f"{self.base_url}/analyses/{analysis_id}/sub-analyses"
        )
        return response.json()

    def get_code_reuse(self, analysis_id: str, sub_analysis_id: str) -> None:
        response = self.session.get(
            f"{self.base_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse"
        )
        return response.json()

    def get_metadata(self, analysis_id: str, sub_analysis_id: str) -> None:
        response = self.session.get(
            f"{self.base_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/metadata"
        )
        return response.json()
