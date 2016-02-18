from .base import TestBasicUnit, TestResultsBasicUnit
from .data import MSM_Results_DNS
from pierky.ripeatlasmonitor.Monitor import Monitor


class TestDNSResult(TestResultsBasicUnit):

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
                "DNSFlags": {
                    "dns_flags": ["ad"]
                },
                "EDNS_4096": {
                    "edns": True,
                    "edns_size": 4096
                },
                "EDNS_DO_on": {
                    "edns": True,
                    "edns_do": True
                },
                "EDNS_DO_off": {
                    "edns": True,
                    "edns_do": False
                },
                "DNSAns_A": {
                    "dns_answers": {
                        "answers": [{"type": "A", "address": "193.0.6.139"}]
                    }
                },
                "DNSAns_A_with_name": {
                    "dns_answers": {
                        "answers": [{"type": "A", "name": "www.ripe.net.", "address": "193.0.6.139"}]
                    }
                },
                "DNSAns_NS": {
                    "dns_answers": {
                        "authorities": [{"type": "NS", "target": "pri.authdns.ripe.net."}]
                    }
                },
                "DNSAns_Add_AAAA": {
                    "dns_answers": {
                        "additionals": [{"type": "AAAA", "address": "2001:67c:e0:0:0:0:0:0/64"}]
                    }
                },
                "DNSAns_Add_A_with_name": {
                    "dns_answers": {
                        "additionals": [{"type": "A", "name": "pri.authdns.ripe.net.", "address": "193.0.9.0/24"}]
                    }
                },
                "DNSAns_A_multiple": {
                    "dns_answers": {
                        "answers": [{"type": "A", "address": "127.0.0.1"},
                                    {"type": "A", "address": "193.0.6.139"}]
                    }
                }
            },
            "actions": {
                "Log": {
                    "kind": "log"
                }
            },
            "measurement-id": MSM_Results_DNS
        }

    def test_dns_flags(self):
        """DNS, flags"""

        self.cfg["matching_rules"][0]["probe_id"] = 10080
        self.cfg["matching_rules"][0]["expected_results"] = ["DNSFlags"]

        self.process_output(True, 1)

    def test_dns_edns(self):
        """DNS, EDNS"""

        self.cfg["matching_rules"][0]["probe_id"] = [11891, 12320]
        self.cfg["matching_rules"][0]["expected_results"] = "EDNS_4096"

        self.process_output(True, 2)

    def test_dns_edns_mismatch(self):
        """DNS, EDNS size mismatch"""

        self.cfg["matching_rules"][0]["probe_id"] = [10080]
        self.cfg["matching_rules"][0]["expected_results"] = "EDNS_4096"

        self.process_output(False, 1)

    def test_dns_edns_do_on(self):
        """DNS, EDNS DO on"""

        self.cfg["matching_rules"][0]["probe_id"] = [11891, 12320, 10080]
        self.cfg["matching_rules"][0]["expected_results"] = "EDNS_DO_on"

        self.process_output(True, 3)

    def test_dns_edns_do_off(self):
        """DNS, EDNS DO off"""

        self.cfg["matching_rules"][0]["probe_id"] = [11891, 12320, 10080]
        self.cfg["matching_rules"][0]["expected_results"] = "EDNS_DO_off"

        self.process_output(False, 3)

    def test_dns_answers_a(self):
        """DNS, answers, A"""

        self.cfg["matching_rules"][0]["probe_id"] = [10080, 11891, 12320]
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_A"

        self.process_output(True, 3)

    def test_dns_answers_a_multi(self):
        """DNS, answers, A, multiple"""

        self.cfg["matching_rules"][0]["probe_id"] = [10080, 11891, 12320]
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_A_multiple"

        self.process_output(True, 3)

    def test_dns_answers_a_with_name(self):
        """DNS, answers, A with name"""

        self.cfg["matching_rules"][0]["probe_id"] = [10080, 11891, 12320]
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_A_with_name"

        self.process_output(True, 3)

    def test_dns_answers_ns(self):
        """DNS, answers, authority, NS, ok"""

        self.cfg["matching_rules"][0]["probe_id"] = [11891, 12320]
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_NS"

        self.process_output(True, 2)

    def test_dns_answers_add_aaaa(self):
        """DNS, answers, additional, AAAA"""

        self.cfg["matching_rules"][0]["probe_id"] = [11891, 12320]
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_Add_AAAA"

        self.process_output(True, 2)

    def test_dns_answers_add_aaaa_mismatch(self):
        """DNS, answers, additional, AAAA, mismatch"""

        self.cfg["matching_rules"][0]["probe_id"] = 10080
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_Add_AAAA"

        self.process_output(False, 1)

    def test_dns_answers_add_a_with_name(self):
        """DNS, answers, additional, A with name"""

        self.cfg["matching_rules"][0]["probe_id"] = 12320
        self.cfg["matching_rules"][0]["expected_results"] = "DNSAns_Add_A_with_name"

        self.process_output(True, 1)
