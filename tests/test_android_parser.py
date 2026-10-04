import unittest
from modules.parsers.android_parser import AndroidParser

class TestAndroidParser(unittest.TestCase):
    def setUp(self):
        self.parser = AndroidParser()

    def test_threadtime_format(self):
        line = "09-11 10:42:13.123  1234  5678 I ActivityManager: Start proc 1234:com.example.app/u0a123"
        event = self.parser.parse_line(line, 1, "logcat.txt")
        self.assertEqual(event["platform"], "android")
        self.assertEqual(event["log_type"], "logcat")
        self.assertEqual(event["pid"], "1234")
        self.assertEqual(event["tid"], "5678")
        self.assertEqual(event["log_level"], "I")
        self.assertEqual(event["tag"], "ActivityManager")
        self.assertEqual(event["event_type"], "application_launch")
        self.assertEqual(event["package_name"], "com.example.app")

    def test_brief_format(self):
        line = "W/PackageManager( 1234): Unknown package com.malware.app"
        event = self.parser.parse_line(line, 1, "logcat.txt")
        self.assertEqual(event["platform"], "android")
        self.assertEqual(event["log_type"], "logcat")
        self.assertEqual(event["pid"], "1234")
        self.assertEqual(event["log_level"], "W")
        self.assertEqual(event["tag"], "PackageManager")

    def test_selinux_denial(self):
        line = "09-11 10:43:00.000   100   200 W SELinux : avc: denied { read } for scontext=u:r:untrusted_app"
        event = self.parser.parse_line(line, 1, "logcat.txt")
        self.assertEqual(event["tag"], "SELinux")
        self.assertEqual(event["type"], "AUTH_FAIL")
        self.assertEqual(event["event_type"], "selinux_denial")

    def test_malformed_line(self):
        line = "Just some random text in the logcat"
        event = self.parser.parse_line(line, 1, "logcat.txt")
        self.assertEqual(event["timestamp_confidence"], "low")

if __name__ == '__main__':
    unittest.main()
