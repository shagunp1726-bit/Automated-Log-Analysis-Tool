import unittest
from modules.parsers.linux_parser import LinuxParser

class TestLinuxParser(unittest.TestCase):
    def setUp(self):
        self.parser = LinuxParser()

    def test_ssh_failed(self):
        line = "Sep 11 10:42:13 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 52341 ssh2"
        event = self.parser.parse_line(line, 1, "auth.log")
        self.assertEqual(event["platform"], "linux")
        self.assertEqual(event["log_type"], "authentication")
        self.assertEqual(event["type"], "AUTH_FAIL")
        self.assertEqual(event["event_type"], "ssh_login_failed")
        self.assertEqual(event["user"], "admin")
        self.assertEqual(event["ip"], "192.168.1.50")
        
    def test_ssh_accepted(self):
        line = "Sep 11 10:43:01 server sshd[1234]: Accepted password for shagun from 192.168.1.50 port 52341 ssh2"
        event = self.parser.parse_line(line, 1, "auth.log")
        self.assertEqual(event["type"], "AUTH_SUCCESS")
        self.assertEqual(event["event_type"], "ssh_login_success")
        self.assertEqual(event["user"], "shagun")

    def test_sudo_usage(self):
        line = "Sep 11 10:45:00 server sudo: shagun : TTY=pts/0 ; PWD=/home/shagun ; USER=root ; COMMAND=/bin/bash"
        event = self.parser.parse_line(line, 1, "auth.log")
        self.assertEqual(event["type"], "PRIV_ESCALATION")
        self.assertEqual(event["event_type"], "sudo_usage")
        self.assertEqual(event["user"], "shagun")
        self.assertEqual(event["commandline"], "/bin/bash")

    def test_syslog_cron(self):
        line = "Sep 11 10:46:00 server CRON[1235]: (root) CMD (/root/backup.sh)"
        event = self.parser.parse_line(line, 1, "syslog")
        self.assertEqual(event["log_type"], "syslog")
        self.assertEqual(event["type"], "PROCESS_CREATE")

    def test_audit_log(self):
        line = "type=USER_LOGIN msg=audit(1630000000.123:456): pid=123 uid=0 exe=\"/usr/sbin/sshd\" res=success"
        event = self.parser.parse_line(line, 1, "audit.log")
        self.assertEqual(event["log_type"], "audit")
        self.assertEqual(event["type"], "AUTH_SUCCESS")
        self.assertEqual(event["pid"], "123")
        self.assertEqual(event["user"], "0")

    def test_malformed_line(self):
        line = "This is a random garbage line"
        event = self.parser.parse_line(line, 1, "auth.log")
        self.assertEqual(event["timestamp_confidence"], "low")

if __name__ == '__main__':
    unittest.main()
