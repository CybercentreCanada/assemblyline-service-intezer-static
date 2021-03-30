import requests

class IntezerStaticClient():
	def __init__(self, apikey=""):
		self.apikey = apikey
		self.headers = { "api_key": self.apikey }
		self.base_url = "https://analyze.intezer.com/api/v2-0"
		self.create_session()

	def create_session(self):
		response = requests.post(self.base_url + "/get-access-token", json=self.headers)
		self.session = requests.session()
		self.session.headers["Authorization"] = self.session.headers["Authorization"] = "Bearer %s" % response.json()["result"]

	def get_hash_results(self, sha256):
		response = self.session.get(self.base_url + "/files/" + sha256)
		
		if response.status_code == 200:
			return response.json()["result"]

	def get_sub_analysis(self, analysis_id):
		response = self.session.get(self.base_url + "/analyses/" + analysis_id + "/sub-analyses")

		return response.json()

	def get_code_reuse(self, analysis_id, sub_analysis_id):
		response = self.session.get(self.base_url + "/analyses/" + analysis_id + "/sub-analyses/" + sub_analysis_id + "/code-reuse")
		return response.json()

	def get_metadata(self, analysis_id, sub_analysis_id):
		response = self.session.get(self.base_url + "/analyses/" + analysis_id + "/sub-analyses/" + sub_analysis_id + "/metadata")

		return response.json()