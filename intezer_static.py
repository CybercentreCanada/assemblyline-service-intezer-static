import json
from intezer_static_client import *

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


class IntezerStatic(ServiceBase):
		def __init__(self, config=None):
			super(IntezerStatic, self).__init__(config)

		def start(self):
			self.log.debug("Intezer Static service started")

		def stop(self):
			self.log.debug("Intezer Static service ended")

		def execute(self, request):
			result = Result()
			sha256 = request.sha256
			api_key = request.get_param("api_key")

			client = IntezerStaticClient(api_key)
			main_api_result = client.get_hash_results(sha256)

			if main_api_result:
				main_kv_section = ResultSection("Intezer Static analysis report", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(main_api_result))
				
				if main_api_result["verdict"] == "malicious":
					main_kv_section.set_heuristic(1)
				elif main_api_result["verdict"] == "suspicious":
					main_kv_section.set_heuristic(2)

				sub_analysis = client.get_sub_analysis(main_api_result["analysis_id"])

				for sub in sub_analysis["sub_analyses"]:
					code_reuse = client.get_code_reuse(main_api_result["analysis_id"], sub["sub_analysis_id"])
					metadata = client.get_metadata(main_api_result["analysis_id"], sub["sub_analysis_id"])

					# Adding the "code reuse" + "metadata" to the subanalysis dictionnary
					sub.update(code_reuse)
					sub.update(metadata)

					# Removing the empty values
					sub.pop("error", None)

					families = sub.pop("families", None)
					extraction_info = sub.pop("extraction_info", None)

					sub_kv_section = ResultSection("Subanalysis report for " + sub["sub_analysis_id"], body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(sub), parent=main_kv_section)
					if families:
						for family in families:
							ResultSection("Family report for the subanalysis", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(family), parent=sub_kv_section)

					if extraction_info:
						for info in extraction_info["processes"]:
							ResultSection("Extraction informations for the subanalysis", body_format=BODY_FORMAT.KEY_VALUE, body=json.dumps(info), parent=sub_kv_section)

				result.add_section(main_kv_section)
			request.result = result