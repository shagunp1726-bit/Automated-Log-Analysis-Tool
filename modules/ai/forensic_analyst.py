from .gemini_client import GeminiClient
from .evidence_builder import EvidenceBuilder
from .prompt_builder import PromptBuilder
from .response_validator import ResponseValidator

class ForensicAnalyst:
    def __init__(self):
        self.client = GeminiClient()
        self.evidence_builder = EvidenceBuilder()
        self.schema = ResponseValidator.get_schema()
        self.playbook_schema = ResponseValidator.get_playbook_schema()

    def analyze_case(self, case_data: dict, action: str = "explain_incident", custom_query: str = None) -> dict:
        """
        Orchestrates the AI forensic analysis for a given action.
        """
        # 1. Build the context
        context_json = self.evidence_builder.build_context(case_data)

        # 2. Build the prompts
        system_instr = PromptBuilder.get_system_instruction()
        query_instr = PromptBuilder.get_query_instruction(action, custom_query)

        final_prompt = f"TASK:\n{query_instr}\n\nCASE DATA:\n{context_json}"

        # 3. Choose Schema based on action
        if action == "custom":
            schema = ResponseValidator.get_custom_schema()
        elif action == "suggest_playbooks":
            schema = self.playbook_schema
        else:
            schema = self.schema

        # 4. Call Gemini
        result = self.client.analyze(system_instr, final_prompt, schema)

        # 5. Validate
        validated_result = ResponseValidator.validate(result, action)

        return validated_result
