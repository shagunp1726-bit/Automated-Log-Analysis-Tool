import unittest
import os
import tempfile
from modules.parsers.detector import ParserDetector

class TestParserDetection(unittest.TestCase):
    def setUp(self):
        self.detector = ParserDetector()

    def _create_temp_file(self, lines):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            f.write("\n".join(lines))
        return path

    def test_detect_linux(self):
        lines = [
            "Sep 11 10:42:13 server sshd[1234]: Failed password for invalid user admin",
            "Sep 11 10:43:01 server sshd[1234]: Accepted password for root",
            "Sep 11 10:45:00 server sudo: user : TTY=pts/0"
        ]
        path = self._create_temp_file(lines)
        try:
            res = self.detector.detect(path)
            self.assertEqual(res["platform"], "linux")
            self.assertEqual(res["parser_name"], "linux_parser")
        finally:
            os.remove(path)

    def test_detect_android(self):
        lines = [
            "09-11 10:42:13.123  1234  5678 I ActivityManager: Start proc",
            "09-11 10:42:14.123  1234  5678 W PackageManager: something",
        ]
        path = self._create_temp_file(lines)
        try:
            res = self.detector.detect(path)
            self.assertEqual(res["platform"], "android")
            self.assertEqual(res["parser_name"], "android_parser")
        finally:
            os.remove(path)

    def test_detect_legacy(self):
        lines = [
            '{"event_id": 4624, "user": "admin"}',
            '{"event_id": 4625, "user": "guest"}'
        ]
        path = self._create_temp_file(lines)
        try:
            res = self.detector.detect(path)
            self.assertEqual(res["platform"], "windows")
            self.assertEqual(res["parser_name"], "legacy_parser")
        finally:
            os.remove(path)

if __name__ == '__main__':
    unittest.main()
