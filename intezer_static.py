from intezer_static_client import IntezerStaticClient

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultKeyValueSection


class IntezerStatic(ServiceBase):
    def __init__(self, config=None) -> None:
        super(IntezerStatic, self).__init__(config)

    def start(self) -> None:
        self.log.debug("Intezer Static service started")

    def stop(self) -> None:
        self.log.debug("Intezer Static service ended")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        sha256 = request.sha256
        api_key = request.get_param("api_key")

        client = IntezerStaticClient(api_key)
        main_api_result = client.get_hash_results(sha256)

        if main_api_result:
            main_kv_section = ResultKeyValueSection("Intezer Static analysis report")
            main_kv_section.update_items(main_api_result)

            if main_api_result["verdict"] == "malicious":
                main_kv_section.set_heuristic(1)
            elif main_api_result["verdict"] == "suspicious":
                main_kv_section.set_heuristic(2)

            sub_analysis = client.get_sub_analysis(main_api_result["analysis_id"])
            try:
                for sub in sub_analysis["sub_analyses"]:
                    code_reuse = client.get_code_reuse(
                        main_api_result["analysis_id"], sub["sub_analysis_id"]
                    )
                    metadata = client.get_metadata(
                        main_api_result["analysis_id"], sub["sub_analysis_id"]
                    )

                    # Adding the "code reuse" + "metadata" to the subanalysis dictionnary
                    sub.update(code_reuse)
                    sub.update(metadata)

                    # Removing the empty values
                    sub.pop("error", None)

                    families = sub.pop("families", None)
                    extraction_info = sub.pop("extraction_info", None)

                    sub_kv_section = ResultKeyValueSection(
                        f"Subanalysis report for {sub['sub_analysis_id']}"
                    )
                    sub_kv_section.update_items(sub)
                    main_kv_section.add_subsection(sub_kv_section)
                    if families:
                        for family in families:
                            family_kv_section = ResultKeyValueSection(
                                "Family report for the subanalysis"
                            )
                            family_kv_section.update_items(family)
                            sub_kv_section.add_subsection(family_kv_section)

                    if extraction_info:
                        for info in extraction_info["processes"]:
                            info_kv_section = ResultKeyValueSection(
                                "Extraction informations for the subanalysis"
                            )
                            info_kv_section.update_items(info)
                            sub_kv_section.add_subsection(info_kv_section)
            except KeyError as e:
                self.log.debug(f"There was a key error: {e}.")
                pass

            result.add_section(main_kv_section)
        request.result = result
