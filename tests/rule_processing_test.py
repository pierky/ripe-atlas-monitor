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

from .base import TestBasicUnit, TestResultsBasicUnit, log_output
from .data import MSM_Results_Traceroute_IPv4
from pierky.ripeatlasmonitor.Monitor import Monitor


class TestRuleProcessing(TestResultsBasicUnit):

    def setUp(self):
        TestResultsBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "actions": "SetLabelTest"
                }
            ],
            "actions": {
                "SetLabelTest": {
                    "kind": "label",
                    "op": "add",
                    "label_name": "Test",
                    "when": "on_match",
                    "scope": "probe"
                },
                "Log": {
                    "kind": "log"
                }
            },
            "measurement-id": MSM_Results_Traceroute_IPv4
        }
 
    def test_rule_no_expres_on_match(self):
        """Rule processing, no expres, on_match"""

        self.assertTupleEqual(self.run_monitor(), (8,0,0))
        self.assertDictEqual(
            self.monitor.internal_labels["probes"],
            {
                '738': set(['Test']),
                '12527': set(['Test']),
                '713': set(['Test']),
                '12120': set(['Test']),
                '832': set(['Test']),
                '24535': set(['Test']),
                '24503': set(['Test']),
                '11821': set(['Test']),
            }
        )

    def test_rule_no_expres_on_mismatch(self):
        """Rule processing, no expres, on_mismatch"""

        self.cfg["actions"]["SetLabelTest"]["when"] = "on_mismatch"

        self.assertTupleEqual(self.run_monitor(), (8,0,0))
        self.assertDictEqual(self.monitor.internal_labels["probes"], {})

    def test_rule_no_expres_always(self):
        """Rule processing, no expres, always"""

        self.cfg["actions"]["SetLabelTest"]["when"] = "always"

        self.assertTupleEqual(self.run_monitor(), (8,0,0))
        self.assertDictEqual(
            self.monitor.internal_labels["probes"],
            {
                '738': set(['Test']),
                '12527': set(['Test']),
                '713': set(['Test']),
                '12120': set(['Test']),
                '832': set(['Test']),
                '24535': set(['Test']),
                '24503': set(['Test']),
                '11821': set(['Test']),
            }
        )

    def test_rule_no_expres_on_match_combo(self):
        """Rule processing, labels with no expres, then rule with expres"""

        self.cfg["matching_rules"][0]["process_next"] = True

        self.cfg["matching_rules"].append({
            "probe_id": [713, 738],
            "actions": "SetLabelOK",
            "process_next": True
        })
        self.cfg["actions"]["SetLabelOK"] = {
            "kind": "label",
            "op": "add",
            "label_name": "OK",
            "when": "on_match",
            "scope": "result"
        }

        self.cfg["matching_rules"].append({
            "internal_labels": "OK",
            "expected_results": "ASPath_1267"
        })

        self.cfg["expected_results"] = {}
        self.cfg["expected_results"]["ASPath_1267"] = {"as_path": "S 1267"}

        # 12 = 8 results from 1st rule ("SetLabelTest") +
        #      2 results from 2nd rule ("SetLabelOK") +
        #      2 results from 3rd rule ("ASPath_1267")
        #  2 = 2 "OK" from 3rd rule ("ASPath_1267")
        self.assertTupleEqual(self.run_monitor(), (12,2,0))

        # "probes" internal labels contain only the "Test" label
        # because rule n. 2 sets a "result" scoped label
        self.assertDictEqual(
            self.monitor.internal_labels["probes"],
            {
                '738': set(['Test']),
                '12527': set(['Test']),
                '713': set(['Test']),
                '12120': set(['Test']),
                '832': set(['Test']),
                '24535': set(['Test']),
                '24503': set(['Test']),
                '11821': set(['Test']),
            }
        )
        
    def test_rule_exclude_then_tag(self):
        """Rule processing, exclude then tag"""

        self.cfg["matching_rules"] = []

        self.cfg["matching_rules"].append({
            "probe_id": [713, 738, 12527],
        })
        self.cfg["matching_rules"].append({
            "process_next": True,
            "actions": ["Log", "SetLabelTest"]
        })
        self.cfg["matching_rules"].append({
            "internal_labels": "Test",
            "expected_results": "ASPath_1267",
            "actions": "Log"
        })

        self.cfg["expected_results"] = {}
        self.cfg["expected_results"]["ASPath_1267"] = {"as_path": "S 1267"}

        # 13: 1st rule: 3 probes +
        #     2nd rule: 5 probes +
        #     3rd rule: 5 probes
        self.assertTupleEqual(self.run_monitor(), (13,0,5))
        self.assertDictEqual(
            self.monitor.internal_labels["probes"],
            {
                '12120': set(['Test']),
                '832': set(['Test']),
                '24535': set(['Test']),
                '24503': set(['Test']),
                '11821': set(['Test']),
            }
        )
