from base import TestBasicUnit, TestResultsBasicUnit, log_output
from data import MSM_Results_Traceroute_IPv4
from pierky.ripeatlasmonitor.Monitor import Monitor


class TestActionLabel(TestResultsBasicUnit):

    def setUp(self):
        TestResultsBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "probe_id": [713,738,832,24535,24503,11821,12120,12527],
                    "descr": "All the probes",
                    "expected_results": ["ASPath_1267"],
                    "actions": ["Label_Result_Matching_via1267", "Log"]
                }
            ],
            "expected_results": {
                "ASPath_1267": {
                    "as_path": "S 1267",
                },
                "ASPath_S_IX_dst": {
                    "as_path": "S IX 32934"
                },
                "DstIP": {
                    "dst_ip": "66.220.156.68"
                }
            },
            "actions": {
                "Label_Result_Matching_via1267": {
                    "when": "on_match",
                    "kind": "label", "op": "add", "label_name": "via1267"
                },
                "Label_Probe_Matching_via1267": {
                    "when": "on_match",
                    "kind": "label", "op": "add", "label_name": "via1267", "scope": "probe"
                },
                "Label_Probe_CheckDstIP": {
                    "when": "on_match",
                    "kind": "label", "op": "add", "label_name": "CheckDstIP", "scope": "probe"
                },
                "Log": {
                    "when": "always",
                    "kind": "log"
                }
            },
            "measurement-id": MSM_Results_Traceroute_IPv4
        }

    def test_action_label_result(self):
        """Action label, result scope"""
        
        # probe 738, 713 match "ASPath_1267"
        # 16 = 8 "result" lines for log +
        #      2 "result" lines for "OK" +
        #      6 "result" lines for "MISMATCH"
        self.assertTupleEqual(self.run_monitor(), (16, 2, 6))
        self.assertDictEqual(self.monitor.internal_labels["probes"], {})

    def test_action_label_probe(self):
        """Action label, probe scope"""

        self.cfg["matching_rules"][0]["actions"] = ["Label_Probe_Matching_via1267", "Log"]
        self.assertTupleEqual(self.run_monitor(), (16, 2, 6))
        self.assertDictEqual(self.monitor.internal_labels["probes"], {
            "738": set(["via1267"]),
            "713": set(["via1267"]),
        })

    def test_action_match_label_result(self):
        """Action label, match label result"""

        self.cfg["matching_rules"][0]["process_next"] = True
        self.cfg["matching_rules"][0]["actions"] = ["Label_Probe_Matching_via1267", "Log"]

        self.cfg["matching_rules"].append({
            "internal_labels": "via1267",
            "expected_results": "DstIP",
            "actions": "Log"
        })

        # 20 = 8 "result" lines for 1st rule log +
        #      2 1st rule "OK" +
        #      6 1st rule "MISMATCH" +
        #      2 "result" lines for 2nd rule log +
        #      2 2nd rule "OK"
        self.assertTupleEqual(self.run_monitor(), (20, 4, 6))
        self.assertDictEqual(self.monitor.internal_labels["probes"], {
            "738": set(["via1267"]),
            "713": set(["via1267"]),
        })
        self.assertListEqual(
            self.results,
            [
                (1, 713, 'ASPath_1267', 'OK'),
                (2, 713, 'DstIP', 'OK'),
                
                (1, 738, 'ASPath_1267', 'OK'),
                (2, 738, 'DstIP', 'OK'),
                
                (1, 832, 'ASPath_1267', 'MISMATCH'),
                
                (1, 11821, 'ASPath_1267', 'MISMATCH'),
                
                (1, 12120, 'ASPath_1267', 'MISMATCH'),
                
                (1, 12527, 'ASPath_1267', 'MISMATCH'),
                
                (1, 24503, 'ASPath_1267', 'MISMATCH'),
                
                (1, 24535, 'ASPath_1267', 'MISMATCH')
            ]
        )

    def test_action_match_label_probe(self):
        """Action label, match label probe"""

        self.cfg["matching_rules"] = []

        # this will match only on the second run,
        # after that probes have been tagged with
        # the "DstIP" label on the first run.
        self.cfg["matching_rules"].append({
            "internal_labels": ["CheckDstIP"],
            "expected_results": "DstIP",
            "actions": "Log"
        })

        # probe 738, 713 match "ASPath_1267"
        self.cfg["matching_rules"].append({
            "reverse": True,
            "internal_labels": ["CheckDstIP"],
            "process_next": True,
            "expected_results": "ASPath_1267",
            "actions": ["Label_Probe_CheckDstIP", "Log"]
        })

        # probe 12120, 12527 match "ASPath_S_IX_dst"
        self.cfg["matching_rules"].append({
            "reverse": True,
            "internal_labels": ["CheckDstIP"],
            "process_next": True,
            "expected_results": "ASPath_S_IX_dst",
            "actions": ["Label_Probe_CheckDstIP", "Log"]
        })

        # 28 = rule n. 2, 16 (8 probes * 2 "result" lines each) +
        #      rule n. 3, 12 (6 probes, 8 - the 2 matched on rule n. 2 and tagged with "CheckDstIP", * 2 "result" lines each)
        #  4 = 4 "OK" (probe 738, 713 for "ASPath_1267", probe 12120, 12527 for "ASPath_S_IX_dst")
        # 10 = 10 "MISMATCH", 6 on rule n. 2 and 4 on rule n. 3
        self.assertTupleEqual(self.run_monitor(), (28, 4, 10))
        self.assertDictEqual(
            self.monitor.internal_labels["probes"],
            {
                '738': set(['CheckDstIP']),
                '12527': set(['CheckDstIP']),
                '713': set(['CheckDstIP']),
                '12120': set(['CheckDstIP'])
            }
        )
        self.assertListEqual(
            self.results,
            [
                (2, 713, 'ASPath_1267', 'OK'),

                (2, 738, 'ASPath_1267', 'OK'),

                (2, 832, 'ASPath_1267', 'MISMATCH'),
                (3, 832, 'ASPath_S_IX_dst', 'MISMATCH'),

                (2, 11821, 'ASPath_1267', 'MISMATCH'),
                (3, 11821, 'ASPath_S_IX_dst', 'MISMATCH'),
                
                (2, 12120, 'ASPath_1267', 'MISMATCH'),
                (3, 12120, 'ASPath_S_IX_dst', 'OK'),
                
                (2, 12527, 'ASPath_1267', 'MISMATCH'),
                (3, 12527, 'ASPath_S_IX_dst', 'OK'),
                
                (2, 24503, 'ASPath_1267', 'MISMATCH'),
                (3, 24503, 'ASPath_S_IX_dst', 'MISMATCH'),
                
                (2, 24535, 'ASPath_1267', 'MISMATCH'),
                (3, 24535, 'ASPath_S_IX_dst', 'MISMATCH')
            ]
        )

        # 24 = 4 probes "OK" + log (8) +
        #      4 probes "MISMATCH" * 2 "expected_results" ("ASPath_1267" and "ASPath_S_IX_dst") + log (16)
        #  4 = 4 probes "OK" (738, 713, 12120, 12527)
        #  8 = 4 probes "MISMATCH" * 2 "expected_results"
        self.assertTupleEqual(self.run_monitor(), (24, 4, 8))
        self.assertListEqual(
            self.results,
            [
                (1, 713, 'DstIP', 'OK'),
                
                (1, 738, 'DstIP', 'OK'),
                
                (2, 832, 'ASPath_1267', 'MISMATCH'),
                (3, 832, 'ASPath_S_IX_dst', 'MISMATCH'),
                
                (2, 11821, 'ASPath_1267', 'MISMATCH'),
                (3, 11821, 'ASPath_S_IX_dst', 'MISMATCH'),
                
                (1, 12120, 'DstIP', 'OK'),
                
                (1, 12527, 'DstIP', 'OK'),
                
                (2, 24503, 'ASPath_1267', 'MISMATCH'),
                (3, 24503, 'ASPath_S_IX_dst', 'MISMATCH'),
                
                (2, 24535, 'ASPath_1267', 'MISMATCH'),
                (3, 24535, 'ASPath_S_IX_dst', 'MISMATCH')
            ]
        )

