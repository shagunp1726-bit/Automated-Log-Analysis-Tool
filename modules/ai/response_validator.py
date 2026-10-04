class ResponseValidator:
    @staticmethod
    def get_schema():
        return {
            "type": "OBJECT",
            "properties": {
                "verdict": {
                    "type": "OBJECT",
                    "properties": {
                        "classification": {"type": "STRING"},
                        "confidence": {"type": "NUMBER"},
                        "severity": {"type": "STRING"}
                    },
                    "required": ["classification", "confidence", "severity"]
                },
                "executive_summary": {"type": "STRING"},
                "scenario": {
                    "type": "OBJECT",
                    "properties": {
                        "title": {"type": "STRING"},
                        "description": {"type": "STRING"}
                    },
                    "required": ["title", "description"]
                },
                "attack_chain": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "stage": {"type": "STRING"},
                            "description": {"type": "STRING"},
                            "confidence": {"type": "NUMBER"},
                            "evidence_ids": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            }
                        },
                        "required": ["stage", "description", "confidence"]
                    }
                },
                "key_findings": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "finding": {"type": "STRING"},
                            "severity": {"type": "STRING"},
                            "confidence": {"type": "NUMBER"},
                            "reason": {"type": "STRING"},
                            "evidence_ids": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            }
                        },
                        "required": ["finding", "severity", "confidence", "reason"]
                    }
                },
                "mitre_analysis": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "technique": {"type": "STRING"},
                            "name": {"type": "STRING"},
                            "reason": {"type": "STRING"},
                            "confidence": {"type": "NUMBER"},
                            "evidence_ids": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            }
                        },
                        "required": ["technique", "name", "reason"]
                    }
                },
                "recommended_actions": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "priority": {"type": "STRING"},
                            "action": {"type": "STRING"},
                            "reason": {"type": "STRING"}
                        },
                        "required": ["priority", "action", "reason"]
                    }
                },
                "next_investigation_steps": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "step": {"type": "STRING"},
                            "reason": {"type": "STRING"},
                            "suggested_query": {"type": "STRING"}
                        },
                        "required": ["step", "reason"]
                    }
                },
                "alternative_explanations": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                },
                "investigation_gaps": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                }
            },
            "required": ["verdict", "executive_summary", "scenario", "key_findings"]
        }

    @staticmethod
    def get_playbook_schema():
        """
        JSON schema for AI-generated playbook suggestions.
        """
        return {
            "type": "OBJECT",
            "properties": {
                "playbooks": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "title": {"type": "STRING"},
                            "severity": {"type": "STRING"},
                            "priority": {"type": "NUMBER"},
                            "rationale": {"type": "STRING"},
                            "mitre_techniques_addressed": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            },
                            "evidence_ids": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            },
                            "phases": {
                                "type": "ARRAY",
                                "items": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "phase": {"type": "STRING"},
                                        "steps": {
                                            "type": "ARRAY",
                                            "items": {
                                                "type": "OBJECT",
                                                "properties": {
                                                    "action": {"type": "STRING"},
                                                    "details": {"type": "STRING"},
                                                    "urgency": {"type": "STRING"}
                                                },
                                                "required": ["action", "details", "urgency"]
                                            }
                                        }
                                    },
                                    "required": ["phase", "steps"]
                                }
                            },
                            "contacts": {
                                "type": "ARRAY",
                                "items": {"type": "STRING"}
                            },
                            "success_criteria": {"type": "STRING"}
                        },
                        "required": ["title", "severity", "priority", "rationale", "phases", "contacts"]
                    }
                },
                "overall_recommendation": {"type": "STRING"},
                "escalation_required": {"type": "BOOLEAN"}
            },
            "required": ["playbooks", "overall_recommendation", "escalation_required"]
        }

    @staticmethod
    def get_custom_schema():
        return {
            "type": "OBJECT",
            "properties": {
                "answer": {"type": "STRING"},
                "evidence_ids": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                }
            },
            "required": ["answer"]
        }

    @staticmethod
    def validate(response: dict, action: str = "explain_incident") -> dict:
        """
        Ensures the JSON response is not malformed.
        """
        if "error" in response:
            return response

        if action == "custom":
            if "answer" not in response:
                return {"error": "Malformed response: missing required key 'answer'"}
            return response

        if action == "suggest_playbooks":
            if "playbooks" not in response:
                return {"error": "Malformed response: missing required key 'playbooks'"}
            if not isinstance(response["playbooks"], list):
                return {"error": "Malformed response: 'playbooks' must be a list"}
            return response

        required_keys = ["verdict", "executive_summary", "scenario", "key_findings"]
        for key in required_keys:
            if key not in response:
                return {"error": f"Malformed response: missing required key '{key}'"}

        return response
