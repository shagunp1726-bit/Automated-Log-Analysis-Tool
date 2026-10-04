"""
Unit tests for AI Hunter Splunk Query Chatbot
Tests SplunkQueryBot, Gemini integration, fallback mechanism, and Flask endpoints.
"""

import sys
import os
import unittest
import json

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.ai.splunk_query_bot import SplunkQueryBot, SPLUNK_RESPONSE_SCHEMA
import app

class TestSplunkBot(unittest.TestCase):
    def setUp(self):
        self.bot = SplunkQueryBot()
        self.test_case = {
            "case_id": "CASE-TEST-001",
            "incident_type": "Brute Force Attack",
            "severity": "HIGH",
            "risk_score": 85,
            "mitre_techniques": [
                {"technique_id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
                {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}
            ],
            "entity_summary": {
                "user": [{"value": "admin", "count": 24}, {"value": "svc_sql", "count": 10}],
                "ip": [{"value": "192.168.1.105", "count": 30}, {"value": "45.33.32.156", "count": 15}],
                "process": [{"value": "powershell.exe", "count": 8}]
            },
            "events": [
                {
                    "timestamp": "2026-09-16 10:00:00",
                    "type": "AUTH_FAIL",
                    "severity": "high",
                    "user": "admin",
                    "ip": "45.33.32.156",
                    "process": "logon.exe",
                    "raw": "Failed logon attempt for admin from 45.33.32.156"
                },
                {
                    "timestamp": "2026-09-16 10:05:00",
                    "type": "PROCESS_CREATE",
                    "severity": "critical",
                    "user": "admin",
                    "ip": "192.168.1.105",
                    "process": "powershell.exe",
                    "raw": "powershell.exe -enc SQBFAFgA"
                }
            ],
            "detections": ["Multiple Failed Logins", "Encoded PowerShell Command"]
        }

    def test_case_context_extraction(self):
        ctx = self.bot.build_case_context(self.test_case)
        self.assertEqual(ctx["case_id"], "CASE-TEST-001")
        self.assertEqual(ctx["incident_type"], "Brute Force Attack")
        self.assertIn("admin", ctx["top_users"])
        self.assertIn("45.33.32.156", ctx["top_ips"])
        self.assertTrue(any("T1110.001" in t for t in ctx["mitre_techniques"]))

    def test_rule_fallback_brute_force(self):
        ctx = self.bot.build_case_context(self.test_case)
        res = self.bot._generate_fallback("find failed logins", ctx, [])
        self.assertIn("splunk_query", res)
        self.assertIn("4625", res["splunk_query"])
        self.assertIn("admin", res["splunk_query"] + res["message"])
        self.assertTrue(len(res["pipeline_stages"]) >= 2)
        self.assertTrue(len(res["suggested_pivots"]) >= 2)

    def test_rule_fallback_powershell(self):
        ctx = self.bot.build_case_context(self.test_case)
        res = self.bot._generate_fallback("powershell executions", ctx, [])
        self.assertIn("splunk_query", res)
        self.assertIn("powershell", res["splunk_query"].lower())
        self.assertIn("pipeline_stages", res)

    def test_flask_api_splunk_chat(self):
        # Inject case into case_store
        case_id = "test-chat-case-123"
        app.case_store[case_id] = dict(self.test_case)
        app.case_store[case_id]["case_id"] = case_id

        client = app.app.test_client()

        # 1. Post a chat message
        post_res = client.post(f"/api/{case_id}/splunk-chat", json={"message": "Show me failed logins for admin"})
        self.assertEqual(post_res.status_code, 200)
        data = post_res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("response", data)
        self.assertIn("splunk_query", data["response"])
        self.assertEqual(len(data.get("history", [])), 2)  # 1 user turn + 1 assistant turn

        # 2. Get history
        hist_res = client.get(f"/api/{case_id}/splunk-chat/history")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.get_json()
        self.assertEqual(len(hist_data.get("history", [])), 2)
        self.assertEqual(hist_data["history"][0]["role"], "user")
        self.assertEqual(hist_data["history"][1]["role"], "assistant")

        # 3. Post a follow-up message (multi-turn)
        followup_res = client.post(f"/api/{case_id}/splunk-chat", json={"message": "Now add a threshold where count > 10"})
        self.assertEqual(followup_res.status_code, 200)
        followup_data = followup_res.get_json()
        self.assertEqual(len(followup_data.get("history", [])), 4)

        # 4. Reset history
        reset_res = client.post(f"/api/{case_id}/splunk-chat/reset")
        self.assertEqual(reset_res.status_code, 200)
        hist_after_reset = client.get(f"/api/{case_id}/splunk-chat/history").get_json()
        self.assertEqual(len(hist_after_reset.get("history", [])), 0)

if __name__ == "__main__":
    unittest.main()
