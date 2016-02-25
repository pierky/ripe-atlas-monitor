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
from .data import MSM_Results_Traceroute_IPv4
from pierky.ripeatlasmonitor.Monitor import Monitor


class TestTracerouteResult(TestResultsBasicUnit):

    def setUp(self):
        TestResultsBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "probe_id": [713,738,832,24535,24503,11821,12120,12527],
                    "expected_results": [],
                    "actions": []
                }
            ],
            "expected_results": {
                "DstAS32934": {
                    "dst_as": 32934
                },
                "ASPath_713_full": {
                    "as_path": "S 1267 1200 32934"
                },
                "ASPath_713_part": {
                    "as_path": "1267 1200"
                },
                "ASPath_738": {
                    "as_path": "S 1267 32934",
                },
                "ASPath_738_ix": {
                    "as_path": "S 1267 IX 32934"
                },
                "ASPath_S_IX_dst": {
                    "as_path": "S IX 32934"
                },
                "Upstream_1200": {
                    "upstream_as": 1200
                },
                "RTT_150": {
                    "rtt": 150
                },
                "RTT_150_tol": {
                    "rtt": 150,
                    "rtt_tolerance": 30
                },
                "DstResponded": {
                    "dst_responded": True
                },
                "ASPath_713_full_AND_DstAS32934": {
                    "as_path": "S 1267 1200 32934",
                    "dst_as": 32934
                },
                "DstIP": {
                    "dst_ip": "66.220.156.68"
                }
            },
            "actions": {
                "Log": {
                    "kind": "log"
                }
            },
            "measurement-id": MSM_Results_Traceroute_IPv4
        }

    def test_dst_as_ok(self):
        """Traceroute, dst_as,"""

        self.cfg["matching_rules"][0]["expected_results"] = ["DstAS32934"]
        self.cfg["matching_rules"][0]["probe_id"] = 24503
        self.cfg["matching_rules"][0]["reverse"] = True

        self.process_output(True, 7)

    def test_dst_as_mismatch(self):
        """Traceroute, dst_as, mismatch"""

        self.cfg["matching_rules"][0]["expected_results"] = ["DstAS32934"]
        self.cfg["matching_rules"][0]["probe_id"] = 24503

        self.process_output(False, 1)

    def test_as_path_713_full_ok(self):
        """Traceroute, as_path, probe ID 713, full"""

        self.cfg["matching_rules"][0]["probe_id"] = 713
        self.cfg["matching_rules"][0]["expected_results"] = ["ASPath_713_full"]

        self.process_output(True, 1)

    def test_as_path_713_partial_ok(self):
        """Traceroute, as_path, probe ID 713, partial"""

        self.cfg["matching_rules"][0]["probe_id"] = 713
        self.cfg["matching_rules"][0]["expected_results"] = ["ASPath_713_part"]

        self.process_output(True, 1)

    def test_as_path_738_no_ixp_ok(self):
        """Traceroute, as_path, probe 738, no IXP"""

        self.cfg["matching_rules"][0]["probe_id"] = 738
        self.cfg["matching_rules"][0]["expected_results"] = ["ASPath_738"]

        self.process_output(True, 1)

    def test_as_path_738_ixp_ok(self):
        """Traceroute, as_path, probe 738, IXP"""

        self.cfg["matching_rules"][0]["probe_id"] = 738
        self.cfg["matching_rules"][0]["expected_results"] = ["ASPath_738_ix"]

        self.process_output(True, 1)

    def test_as_path_S_IX_dst_ok(self):
        """Traceroute, as_path, probe 12120, 12527, S IX dst"""

        self.cfg["matching_rules"][0]["probe_id"] = [12120, 12527]
        self.cfg["matching_rules"][0]["expected_results"] = ["ASPath_S_IX_dst"]

        self.process_output(True, 2)

    def test_upstream_as_ok(self):
        """Traceroute, upstream_as, probe 713"""

        self.cfg["matching_rules"][0]["probe_id"] = [713]
        self.cfg["matching_rules"][0]["expected_results"] = ["Upstream_1200"]

        self.process_output(True, 1)

    def test_upstream_as_mismatch(self):
        """Traceroute, upstream_as, probe 12120, mismatch"""

        self.cfg["matching_rules"][0]["probe_id"] = 12120
        self.cfg["matching_rules"][0]["expected_results"] = ["Upstream_1200"]

        self.process_output(False, 1)

    def test_rtt_ok(self):
        """Traceroute, rtt"""

        self.cfg["matching_rules"][0]["probe_id"] = [832, 24503]
        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["expected_results"] = ["RTT_150"]

        self.process_output(True, 6)

    def test_rtt_mismatch(self):
        """Traceroute, rtt, mismatch"""

        self.cfg["matching_rules"][0]["probe_id"] = [832]
        self.cfg["matching_rules"][0]["expected_results"] = ["RTT_150"]

        self.process_output(False, 1)

    def test_rtt_tolerance_ok(self):
        """Traceroute, rtt with tolerance"""

        self.cfg["matching_rules"][0]["probe_id"] = [832]
        self.cfg["matching_rules"][0]["expected_results"] = ["RTT_150_tol"]

        self.process_output(True, 1)

    def test_dst_responded_ok(self):
        """Traceroute, dst_responded"""

        self.cfg["matching_rules"][0]["probe_id"] = 24503
        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["expected_results"] = ["DstResponded"]

        self.process_output(True, 7)

    def test_dst_responded_mismatch(self):
        """Traceroute, dst_responded, mismatch"""

        self.cfg["matching_rules"][0]["probe_id"] = 24503
        self.cfg["matching_rules"][0]["expected_results"] = ["DstResponded"]

        self.process_output(False, 1)

    def test_dst_responded_rtt(self):
        """Traceroute, 2 expres, dst_responded and rtt"""

        self.cfg["matching_rules"][0]["probe_id"] = [832, 24503]
        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["expected_results"] = ["DstResponded",
                                                             "RTT_150"]

        self.process_output(True, 6*2)

    def test_as_path_dst_as_1(self):
        """Traceroute, 1 expres, as_path and dst_as"""

        self.cfg["matching_rules"][0]["probe_id"] = 713
        self.cfg["matching_rules"][0]["expected_results"] = [
            "ASPath_713_full_AND_DstAS32934"
        ]

        self.process_output(True, 1)

    def test_as_path_dst_as_2(self):
        """Traceroute, 2 expres, as_path and dst_as"""

        self.cfg["matching_rules"][0]["probe_id"] = 713
        self.cfg["matching_rules"][0]["expected_results"] = ["ASPath_713_full",
                                                             "DstAS32934"]

        self.process_output(True, 1*2)

    def test_dst_ip(self):
        """Traceroute, dst_ip"""

        self.cfg["matching_rules"][0]["expected_results"] = "DstIP"

        self.process_output(True, 8)
