import unittest
from modules.parsers.legacy_parser import LegacyParser

class TestLegacyParserRegression(unittest.TestCase):
    def setUp(self):
        self.parser = LegacyParser()

    def test_windows_json(self):
        line = '{"event_id": 4624, "message": "logged in successfully", "user": "admin", "ip": "10.0.0.1", "timestamp": "2023-01-01 12:00:00"}'
        event = self.parser.parse_line(line, 1, "security.json")
        self.assertEqual(event["type"], "AUTH_SUCCESS")
        self.assertEqual(event["user"], "admin")
        self.assertEqual(event["ip"], "10.0.0.1")

    def test_network_log(self):
        line = "Connection to 192.168.1.100 port 80 blocked"
        event = self.parser.parse_line(line, 1, "firewall.log")
        self.assertEqual(event["type"], "NETWORK_CONN")
        self.assertEqual(event["ip"], "192.168.1.100")

if __name__ == '__main__':
    unittest.main()
