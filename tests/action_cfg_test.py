# Copyright (C) 2016 Pier Carlo Chiodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from .data import MSM_Ping_IPv6_Ongoing
from .base import TestBasicUnit
from pierky.ripeatlasmonitor.Errors import *
from pierky.ripeatlasmonitor.Monitor import Monitor

class TestActionCfg(TestBasicUnit):

    def setUp(self):
        TestBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "descr": "Any",
                    "expected_results": ["test"],
                    "actions": "test"
                }
            ],
            "expected_results": {
                "test": {
                    "rtt": 10
                }
            },
            "actions": {
                "test": {}
            },
            "measurement-id": MSM_Ping_IPv6_Ongoing
        }

    def test_on_match(self):
        """Action on_match"""

        self.cfg["actions"]["test"] = {
            "kind": "log",
            "when": "on_match"
        }

        self.create_monitor()

    def test_log(self):
        """Action log"""

        self.cfg["actions"]["test"] = {
            "kind": "log",
            "descr": "Test"
        }

        self.create_monitor()

    def test_log_unk_attr(self):
        """Action log, unknown attribute"""

        self.cfg["actions"]["test"] = {
            "kind": "log",
            "descr": "Test",
            "unknown": 123
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown configuration field")

    def test_email(self):
        """Action email"""

        self.cfg["actions"]["test"] = {
            "kind": "email",
            "descr": "Test",
            "from_addr": "pierky@pierky.com",
            "to_addr": "pierky@pierky.com",
            "subject": "ripe-atlas-monitor warning",
            "smtp_host": "donotexist-smtp-server.example.com"
        }

        self.create_monitor()

    def test_email_unk_attr(self):
        """Action email, unknown attribute"""

        self.cfg["actions"]["test"] = {
            "kind": "email",
            "descr": "Test",
            "from_addr": "pierky@pierky.com",
            "to_addr": "pierky@pierky.com",
            "subject": "ripe-atlas-monitor warning",
            "smtp_host": "donotexist-smtp-server.example.com",
            "unknown": 123
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown configuration field")

    def test_email_multiple_recipients(self):
        """Action email, multiple recipients"""

        self.cfg["actions"]["test"] = {
            "kind": "email",
            "descr": "Test",
            "from_addr": "pierky@pierky.com",
            "to_addr": [ "pierky@pierky.com", "unknown@email.com" ],
            "subject": "ripe-atlas-monitor warning",
            "smtp_host": "donotexist-smtp-server.example.com"
        }

        self.create_monitor()

    def test_email_invalid_from(self):
        """Action email, invalid from"""

        self.cfg["actions"]["test"] = {
            "kind": "email",
            "descr": "Test",
            "from_addr": "pierky",
            "to_addr": [ "pierky@pierky.com", "unknown@email.com" ],
            "subject": "ripe-atlas-monitor warning",
            "smtp_host": "donotexist-smtp-server.example.com"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid email address in from_addr")

    def test_email_invalid_to(self):
        """Action email, invalid to"""

        self.cfg["actions"]["test"] = {
            "kind": "email",
            "descr": "Test",
            "from_addr": "pierky@pierky.com",
            "to_addr": "pierky",
            "subject": "ripe-atlas-monitor warning",
            "smtp_host": "donotexist-smtp-server.example.com"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid email address in to_addr")

    def test_email_missing_attrs(self):
        """Action email, missing attributes"""

        self.cfg["actions"]["test"] = {
            "kind": "email"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing SMTP server host")

        self.cfg["actions"]["test"]["smtp_host"] = \
            "donotexist-smtp-server.example.com"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing subject")

        self.cfg["actions"]["test"]["subject"] = "ripe-atlas-monitor warning"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing from address")

        self.cfg["actions"]["test"]["from_addr"] = "pierky@pierky.com"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing recipient address")

        self.cfg["actions"]["test"]["to_addr"] = "pierky@pierky.com"

        self.create_monitor()

    def test_run(self):
        """Action run"""

        self.cfg["actions"]["test"] = {
            "kind": "run",
            "path": "true",
            "env_prefix": "TEST_"
        }

        self.create_monitor()

    def test_run_missing_attrs(self):
        """Action run, missing attributes"""

        self.cfg["actions"]["test"] = {
            "kind": "run"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing mandatory field: path")

    def test_run_wrong_var(self):
        """Action run, wrong variable"""

        self.cfg["actions"]["test"] = {
            "kind": "run",
            "path": "program",
            "args": ["command", "-o", "--option", "$BadName"]
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid variable")

    def test_run_args(self):
        """Action run, good variables"""

        self.cfg["actions"]["test"] = {
            "kind": "run",
            "path": "program",
            "args": ["command", "-o", "--option", "-msm", "$MsmID", "$ResultCreated"]
        }

        self.create_monitor()

    def test_syslog_udp(self):
        """Action syslog, udp"""

        self.cfg["actions"]["test"] = {
            "kind": "syslog",
            "socket": "udp",
            "host": "127.0.0.1",
            "port": 514,
            "facility": "user",
            "priority": "warning"
        }

        self.create_monitor()

        self.cfg["actions"]["test"]["host"] = "syslog.example.com"

        self.create_monitor()

        self.cfg["actions"]["test"]["host"] = "2001:DB8::1"

        self.create_monitor()

    def test_syslog_file(self):
        """Action syslog, file"""

        self.cfg["actions"]["test"] = {
            "kind": "syslog",
            "socket": "file",
            "file": "/dev/log"
        }

        self.create_monitor()

    def test_syslog_missingattrs(self):
        """Action syslog, missing attributes"""

        self.cfg["actions"]["test"] = {
            "kind": "syslog",
            "socket": "file",
            "file": ""
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing file.")

        self.cfg["actions"]["test"] = {
            "kind": "syslog",
            "socket": "",
            "host": "",
            "port": None,
            "facility": "",
            "priority": ""
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing socket.")

        self.cfg["actions"]["test"]["socket"] = "tcp"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing host.")

        self.cfg["actions"]["test"]["host"] = "127.0.0.1"

        self.create_monitor()

        self.cfg["actions"]["test"]["socket"] = "file"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing file.")

    def test_syslog_priorities(self):
        """Action syslog, priorities"""

        self.cfg["actions"]["test"] = {
            "kind": "syslog",
            "socket": "file",
            "file": "/dev/log"
        }

        for p in ["alert", "crit", "critical", "debug", "emerg", "panic",
                  "err", "error", "info", "notice", "warn", "warning"]:
            self.cfg["actions"]["test"]["priority"] = p
            self.create_monitor()

        self.cfg["actions"]["test"]["priority"] = "test"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid priority: test")

    def test_label(self):
        """Action label"""

        self.cfg["actions"]["test"] = {
            "kind": "label",
            "op": "add",
            "label_name": "test"
        }

        self.create_monitor()

        self.cfg["actions"]["test"]["scope"] = "probe"
        self.create_monitor()

        self.cfg["actions"]["test"]["op"] = "del"
        self.create_monitor()

    def test_label_missing_attrs(self):
        """Action label, missing attributes"""

        self.cfg["actions"]["test"] = {
            "kind": "label"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing mandatory field: label_name")

        self.cfg["actions"]["test"]["label_name"] = "test"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing mandatory field: op")

        self.cfg["actions"]["test"]["op"] = "add"
        self.create_monitor()

    def test_label_invalid_attrs(self):
        """Action label, invalid attributes"""

        self.cfg["actions"]["test"] = {
            "kind": "label",
            "op": "xx",
            "label_name": "test",
            "scope": "xx"
        }
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid label operation: xx.")

        self.cfg["actions"]["test"]["op"] = "add"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid label scope: xx.")

        self.cfg["actions"]["test"]["scope"] = "probe"
        self.create_monitor()

