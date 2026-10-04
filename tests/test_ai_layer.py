import unittest
import json
from unittest.mock import patch, MagicMock

from modules.ai.response_validator import ResponseValidator
from modules.ai.evidence_builder import EvidenceBuilder
from modules.ai.forensic_analyst import ForensicAnalyst

class TestAILayer(unittest.TestCase):
    def test_response_validator_valid(self):
        valid_response = {
            "verdict": {
                "classification": "malicious",
                "confidence": 0.9,
                "severity": "high"
            },
            "executive_summary": "Test summary",
            "scenario": {
                "title": "Test Title",
                "description": "Test Description"
            },
            "key_findings": []
        }
        validated = ResponseValidator.validate(valid_response)
        self.assertNotIn("error", validated)
        self.assertEqual(validated["executive_summary"], "Test summary")

    def test_response_validator_invalid(self):
        invalid_response = {
            "verdict": {}
            # Missing other required keys
        }
        validated = ResponseValidator.validate(invalid_response)
        self.assertIn("error", validated)

    def test_evidence_builder_aggregation(self):
        builder = EvidenceBuilder()
        
        # Create 10 identical events
        events = []
        for i in range(10):
            events.append({
                "event_id": f"EVT-TEST{i}",
                "timestamp": "2026-01-01T10:00:00",
                "type": "AUTH_FAIL",
                "severity": "high",
                "user": "admin",
                "ip": "10.0.0.1",
                "process": "sshd",
                "raw": "Failed password for admin"
            })
            
        case_data = {
            "case_id": "TEST-123",
            "risk_score": 85,
            "events": events
        }
        
        context_str = builder.build_context(case_data)
        context = json.loads(context_str)
        
        # It should cap identical events at 5, plus 1 for aggregation_stats
        self.assertEqual(len(context["evidence_summary"]), 6)
        
        stats = context["evidence_summary"][-1]["aggregation_stats"]
        self.assertEqual(stats["AUTH_FAIL|admin|10.0.0.1|sshd"], 10)

    @patch('modules.ai.gemini_client.GeminiClient.analyze')
    def test_forensic_analyst_orchestrator(self, mock_analyze):
        mock_analyze.return_value = {
            "verdict": {"classification": "suspicious", "confidence": 0.8, "severity": "medium"},
            "executive_summary": "Orchestrator test",
            "scenario": {"title": "Test", "description": "Test"},
            "key_findings": []
        }
        
        analyst = ForensicAnalyst()
        result = analyst.analyze_case({"case_id": "TEST-123", "events": []}, "explain_incident")
        
        self.assertNotIn("error", result)
        self.assertEqual(result["executive_summary"], "Orchestrator test")
        mock_analyze.assert_called_once()

if __name__ == '__main__':
    unittest.main()
