import os
import unittest
from modules.parsers.detector import ParserDetector
from modules.parser import parse_logs
from modules.auth_detector import detect_attacks
from modules.mitre_mapper import map_mitre

class TestSampleLogs(unittest.TestCase):
    def setUp(self):
        self.sample_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_logs")
        self.detector = ParserDetector()

    def test_sample_files_exist(self):
        expected_files = ["windows_attack.log", "linux_system.log", "android_logcat.log"]
        for fn in expected_files:
            path = os.path.join(self.sample_dir, fn)
            self.assertTrue(os.path.isfile(path), f"Sample file {fn} does not exist at {path}")

    def test_windows_sample_log(self):
        path = os.path.join(self.sample_dir, "windows_attack.log")
        detect_result = self.detector.detect(path)
        self.assertEqual(detect_result["platform"], "windows")
        self.assertEqual(detect_result["parser_name"], "legacy_parser")

        events, diagnostics = parse_logs([path])
        self.assertGreaterEqual(len(events), 20)
        self.assertEqual(diagnostics[0]["unknown_lines"], 0)

        attacks = detect_attacks(events)
        self.assertIn("Brute Force Login Attempt", attacks)
        self.assertIn("Privilege Escalation Activity", attacks)
        self.assertIn("Unauthorized USB Usage", attacks)

        techniques = map_mitre(events)
        self.assertGreater(len(techniques), 10)

    def test_linux_sample_log(self):
        path = os.path.join(self.sample_dir, "linux_system.log")
        detect_result = self.detector.detect(path)
        self.assertEqual(detect_result["platform"], "linux")
        self.assertEqual(detect_result["parser_name"], "linux_parser")
        self.assertGreater(detect_result["confidence"], 50.0)

        events, diagnostics = parse_logs([path])
        self.assertGreaterEqual(len(events), 15)
        self.assertEqual(diagnostics[0]["unknown_lines"], 0)

        attacks = detect_attacks(events)
        self.assertIn("Brute Force Login Attempt", attacks)
        self.assertIn("Privilege Escalation Activity", attacks)

        techniques = map_mitre(events)
        self.assertGreater(len(techniques), 5)

    def test_android_sample_log(self):
        path = os.path.join(self.sample_dir, "android_logcat.log")
        detect_result = self.detector.detect(path)
        self.assertEqual(detect_result["platform"], "android")
        self.assertEqual(detect_result["parser_name"], "android_parser")
        self.assertGreater(detect_result["confidence"], 50.0)

        events, diagnostics = parse_logs([path])
        self.assertGreaterEqual(len(events), 10)
        self.assertEqual(diagnostics[0]["unknown_lines"], 0)

        # Check Android specific extractions
        package_names = [e.get("package_name") for e in events if e.get("package_name")]
        self.assertTrue(any("com.secure.bank.authenticator" in pkg for pkg in package_names))

        selinux_denials = [e for e in events if e.get("event_type") == "selinux_denial"]
        self.assertGreaterEqual(len(selinux_denials), 2)

    def test_sample_routes(self):
        from app import app
        client = app.test_client()

        # Test sample loaders
        for plat in ["windows", "linux", "android"]:
            resp = client.get(f"/sample/{plat}", follow_redirects=False)
            self.assertEqual(resp.status_code, 302, f"Failed for platform {plat}")
            self.assertIn("/siem/sample-", resp.headers["Location"])

        # Test sample download
        dl_resp = client.get("/download-sample/windows_attack.log")
        self.assertEqual(dl_resp.status_code, 200)
        self.assertIn(b"WORKSTATION-01", dl_resp.data)
        dl_resp.close()

        dl_resp_linux = client.get("/download-sample/linux_system.log")
        self.assertEqual(dl_resp_linux.status_code, 200)
        self.assertIn(b"sshd", dl_resp_linux.data)
        dl_resp_linux.close()

        dl_resp_android = client.get("/download-sample/android_logcat.log")
        self.assertEqual(dl_resp_android.status_code, 200)
        self.assertIn(b"ActivityManager", dl_resp_android.data)
        dl_resp_android.close()

        # Nonexistent file should 404
        dl_fail = client.get("/download-sample/malicious_hack.sh")
        self.assertEqual(dl_fail.status_code, 404)
        dl_fail.close()

if __name__ == '__main__':
    unittest.main()

