from .base import TestResultsBasicUnit
from .data import MSM_Results_Traceroute_IPv4
from pierky.ripeatlasmonitor.Monitor import Monitor

class TestMatchingProbes(TestResultsBasicUnit):

    def setUp(self):
        TestResultsBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "actions": "Log"
                }
            ],
            "actions": {
                "Log": {"kind": "log"}
            },
            "measurement-id": MSM_Results_Traceroute_IPv4
        }

        self.all_probes = [713, 738, 832, 24535, 24503, 11821, 12120, 12527]

    def run_and_match(self, exp_res):
        self.run_monitor()
        matching_probes = []
        for result in self.results:
            matching_probes.append(result[1])
        self.assertListEqual(sorted(exp_res), sorted(matching_probes))

    def test_any(self):
        """Matching probe, any"""

        self.run_and_match(self.all_probes)


    def test_id(self):
        """Matching probe, id"""

        self.cfg["matching_rules"][0]["probe_id"] = 713
        self.run_and_match([713])

    def test_src_as(self):
        """Matching probe, src_as"""

        self.cfg["matching_rules"][0]["src_as"] = 20912
        self.run_and_match([713])

    def test_src_country(self):
        """Matching probe, src_country"""

        self.cfg["matching_rules"][0]["src_country"] = "IT"
        self.run_and_match(self.all_probes)

    def test_src_country_and_src_as(self):
        """Matching probe, src_country and src_as"""

        self.cfg["matching_rules"][0]["src_country"] = "IT"
        self.cfg["matching_rules"][0]["src_as"] = [20912, 137]
        self.run_and_match([713, 12120])

    def test_reverse_id(self):
        """Matching probe, reverse id"""

        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["probe_id"] = [713, 738]
        self.run_and_match([832, 24535, 24503, 11821, 12120, 12527])

    def test_reverse_src_as(self):
        """Matching probe, reverse src_as"""

        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["src_as"] = [20912, 137]
        self.run_and_match([738, 832, 24535, 24503, 11821, 12527])

    def test_reverse_country(self):
        """Matching probe, reverse src_country"""

        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["src_country"] = "IT"
        self.run_and_match([])

    def test_reverse_country_and_src_as(self):
        """Matching probe, reverse src_country and src_as"""

        self.cfg["matching_rules"][0]["reverse"] = True
        self.cfg["matching_rules"][0]["src_country"] = "IT"
        self.cfg["matching_rules"][0]["src_as"] = [20912, 137]
        self.run_and_match([738, 832, 24535, 24503, 11821, 12527])

    def test_reverse_any(self):
        """Matching probe, reverse any"""

        self.cfg["matching_rules"][0]["reverse"] = True
        self.run_and_match([])
