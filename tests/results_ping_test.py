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

from .base import TestBasicUnit, TestResultsBasicUnit
from .data import MSM_Results_Ping_IPv4
from pierky.ripeatlasmonitor.Monitor import Monitor


class TestPingResult(TestResultsBasicUnit):

    def setUp(self):
        TestResultsBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "expected_results": [],
                    "actions": []
                }
            ],
            "expected_results": {
                "RTT_30": {
                    "rtt": 30
                },
                "RTT_30_tol": {
                    "rtt": 30,
                    "rtt_tolerance": 50
                },
                "DstResponded": {
                    "dst_responded": True
                },
                "DstIP": {
                    "dst_ip": "193.170.114.242"
                }
            },
            "actions": {
                "Log": {
                    "kind": "log"
                }
            },
            "measurement-id": MSM_Results_Ping_IPv4
        }

    def test_rtt_ok(self):
        """Ping, rtt"""

        self.cfg["matching_rules"][0]["probe_id"] = [10025, 13939]
        self.cfg["matching_rules"][0]["expected_results"] = ["RTT_30"]

        self.process_output(True, 2)

    def test_rtt_mismatch(self):
        """Ping, rtt, mismatch"""

        self.cfg["matching_rules"][0]["probe_id"] = [3207, 3183, 11421]
        self.cfg["matching_rules"][0]["expected_results"] = ["RTT_30"]

        self.process_output(False, 3)

    def test_rtt_tolerance_ok(self):
        """Ping, rtt with tolerance"""

        self.cfg["matching_rules"][0]["probe_id"] = [3183, 3207, 10025, 11421]
        self.cfg["matching_rules"][0]["expected_results"] = ["RTT_30_tol"]

        self.process_output(True, 4)

    def test_dst_responded_ok(self):
        """Ping, dst_responded"""

        self.cfg["matching_rules"][0]["expected_results"] = ["DstResponded"]

        self.process_output(True, 5)

    def test_dst_ip(self):
        """Ping, dst_ip"""

        self.cfg["matching_rules"][0]["expected_results"] = ["DstIP"]

        self.process_output(True, 5)
