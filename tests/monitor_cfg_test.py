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

from .data import *
from .base import TestBasicUnit
from pierky.ripeatlasmonitor.Errors import *
from pierky.ripeatlasmonitor.ExpResCriteria import CRITERIA_CLASSES
from pierky.ripeatlasmonitor.Monitor import Monitor

class TestMonitorCfg(TestBasicUnit):

    FP_AAAA = "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"
    FP_AABB = "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:BB"

    def setUp(self):
        TestBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [
                {
                    "descr": "Any",
                    "expected_results": ["test"]
                }
            ],
            "expected_results": {
                "test": {
                }
            },
            "measurement-id": MSM_Ping_IPv6_Ongoing
        }

        # contains items in the form "<CRITERION_NAME>": <valid_value> for each
        # expected result criterion
        self.criteria = {
            "as_path": ["123 456 789"],
            "upstream_as": [123, 456],
            "dst_as": [123, 456],
            "rtt": 10,
            "dst_responded": True,
            "dst_ip": "127.0.0.1",
            "cert_fp": TestMonitorCfg.FP_AAAA,
            "dns_rcode": "NOERROR",
            "dns_flags": "ad",
            "edns": True,
            "dns_answers": {"answers": [{"type": "A", "address": "127.0.0.1"}]}
        }

    def add_criterion(self, criterion_name):
        self.cfg["expected_results"]["test"][criterion_name] = \
            self.criteria[criterion_name]
        self.criteria.pop(criterion_name)

    def verify_unavailable_attrs(self):
        unavailable_attrs = self.criteria

        for attr_name, attr_val in unavailable_attrs.items():
            self.cfg["expected_results"]["test"] = {
                attr_name: attr_val
            }
            self.create_monitor(exp_exc=ConfigError,
                                exp_msg="it is available only on")

    def verify_expres_descr(self, v):
        expres_descr = str(self.created_monitor.expected_results["test"])
        self.assertEqual(expres_descr, v)

    def test_invalid_monitor_name_or_cfg(self):
        """Monitor, invalid name or config"""
        self.cfg = 1

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid monitor name or configuration type:")

    def test_monitor(self):
        """Monitor, basic tests"""

        self.cfg.pop("measurement-id")

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing measurement ID")

        self.cfg["measurement-id"] = MSM_Ping_IPv6_Stopped
        self.cfg["stream"] = True
        self.add_criterion("rtt")

        monitor = self.create_monitor(exp_exc=ConfigError,
                                      exp_msg="Can't use results streaming")

    def test_expres(self):
        """Expected results with no criteria"""

        self.cfg["expected_results"]["test"] = {}

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="No criteria found")

    def test_no_expres(self):
        """No expected results"""

        self.cfg["matching_rules"][0] = {
            "descr": "Any"
        }
        self.add_criterion("rtt")

        self.create_monitor()

    def test_criteria(self):
        """All criteria considered"""

        self.assertListEqual(
            sorted([cr_cl.CRITERION_NAME for cr_cl in CRITERIA_CLASSES]),
            sorted([cr_name for cr_name in self.criteria.keys()])
        )
   
    def test_expres_ping(self):
        """Expected results, ping"""

        self.add_criterion("rtt")
        self.add_criterion("dst_responded")
        self.add_criterion("dst_ip")

        self.create_monitor()

        self.verify_unavailable_attrs()

    def test_expres_traceroute(self):
        """Expected results, traceroute"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing

        self.add_criterion("as_path")
        self.add_criterion("upstream_as")
        self.add_criterion("dst_as")
        self.add_criterion("rtt")
        self.add_criterion("dst_responded")
        self.add_criterion("dst_ip")

        self.create_monitor()

        self.verify_unavailable_attrs()

        self.cfg["expected_results"]["test"] = {
            "unknown": 1
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown configuration field")

    def test_expres_sslcert(self):
        """Expected result, sslcert"""

        self.cfg["measurement-id"] = MSM_Results_SSLCert

        self.add_criterion("cert_fp")
        self.add_criterion("dst_ip")
        self.add_criterion("dst_responded")

        self.create_monitor()

        self.verify_unavailable_attrs()

    def test_expres_dns(self):
        """Expected result, dns"""

        self.cfg["measurement-id"] = MSM_Results_DNS

        self.add_criterion("dns_flags")
        self.add_criterion("edns")
        self.add_criterion("dns_answers")
        self.add_criterion("dns_rcode")

        self.create_monitor()

        self.verify_unavailable_attrs()

    def test_criterion_dstas(self):
        """Criterion dst_as"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing
        self.cfg["expected_results"]["test"] = {
                "dst_as": "123"
        }

        self.create_monitor()
        self.verify_expres_descr("Destination AS: 123")

        self.cfg["expected_results"]["test"] = {
                "dst_as": ["123", "456"]
        }

        self.create_monitor()
        self.verify_expres_descr("Destination AS: 123, 456")

        self.cfg["expected_results"]["test"] = {
                "dst_as": "IX"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'IX'")

    def test_criterion_as_path(self):
        """Criterion as_path"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing
        self.cfg["expected_results"]["test"] = {
                "as_path": "123"
        }

        self.create_monitor()
        self.verify_expres_descr("AS path: 123")

        self.cfg["expected_results"]["test"] = {
                "as_path": "123 456 789"
        }

        self.create_monitor()
        self.verify_expres_descr("AS path: 123 456 789")

        self.cfg["expected_results"]["test"] = {
                "as_path": ["123 456", "789 123"]
        }

        self.create_monitor()
        self.verify_expres_descr("AS path: 123 456, 789 123")

        self.cfg["expected_results"]["test"] = {
                "as_path": "aaa"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid ASN: aaa")

        self.cfg["expected_results"]["test"] = {
                "as_path": "S 123 IX"
        }

        self.create_monitor()
        self.verify_expres_descr("AS path: S 123 IX")

        self.cfg["expected_results"]["test"] = {
            "as_path": ["S 123 456", "S 123 IX 456"]
        }

        self.create_monitor()
        self.verify_expres_descr("AS path: S 123 456, S 123 IX 456")

        self.cfg["expected_results"]["test"] = {
            "as_path": "abc 123 def"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid ASN: abc")

    def test_criterion_upstreamas(self):
        """Criterion upstream_as"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing
        self.cfg["expected_results"]["test"] = {
                "upstream_as": "123"
        }

        self.create_monitor()
        self.verify_expres_descr("Target upstream AS: 123")

        self.cfg["expected_results"]["test"] = {
                "upstream_as": ["123", "456"]
        }

        self.create_monitor()
        self.verify_expres_descr("Target upstream AS: 123, 456")

        self.cfg["expected_results"]["test"] = {
                "upstream_as": "IX"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'IX'")

    def test_criterion_rtt(self):
        """Criterion rtt"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing
        self.cfg["expected_results"]["test"] = {
                "rtt": 100
        }

        self.create_monitor()
        self.verify_expres_descr("RTT must be less than 100ms")

        self.cfg["expected_results"]["test"] = {
                "rtt": "100"
        }

        self.create_monitor()
        self.verify_expres_descr("RTT must be less than 100ms")

        self.cfg["expected_results"]["test"] = {
                "rtt": "aaa"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'aaa'")

        self.cfg["expected_results"]["test"] = {
                "rtt": 100,
                "rtt_tolerance": 100
        }

        self.create_monitor()
        self.verify_expres_descr("RTT must be within 100ms +/- 100%")

        self.cfg["expected_results"]["test"]["rtt_tolerance"] = "100"

        self.create_monitor()
        self.verify_expres_descr("RTT must be within 100ms +/- 100%")

        self.cfg["expected_results"]["test"]["rtt_tolerance"] = "bbb"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'bbb'")

    def test_criterion_dst_responded(self):
        """Criterion dst_responded"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing
        self.cfg["expected_results"]["test"] = {
                "dst_responded": True
        }

        self.create_monitor()
        self.verify_expres_descr("Destination must respond")

        self.cfg["expected_results"]["test"]["dst_responded"] = False
        self.create_monitor()
        self.verify_expres_descr("Destination must not respond")

        for v in ["y", "yes", "t", "true", "on", "1", "n", "no", "f", "false",
                  "off", "0"]:
            self.cfg["expected_results"]["test"]["dst_responded"] = v
            self.create_monitor()

        self.cfg["expected_results"]["test"]["dst_responded"] = "a"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'a'")

    def test_criterion_dstip(self):
        """Criterion dst_ip"""

        self.cfg["measurement-id"] = MSM_Traceroute_IPv6_Ongoing
        self.cfg["expected_results"]["test"] = {
                "dst_ip": "127.0.0.1"
        }

        self.create_monitor()
        self.verify_expres_descr("Destination IP must be 127.0.0.1")

        self.cfg["expected_results"]["test"]["dst_ip"] = "2001:DB8::1"
        self.create_monitor()
        self.verify_expres_descr("Destination IP must be 2001:db8::1")

        self.cfg["expected_results"]["test"]["dst_ip"] = "192.168.0.0/24"
        self.create_monitor()
        self.verify_expres_descr("Destination IP must fall into 192.168.0.0/24")

        self.cfg["expected_results"]["test"]["dst_ip"] = "2001:DB8::0/64"
        self.create_monitor()
        self.verify_expres_descr("Destination IP must fall into 2001:db8::/64")

        self.cfg["expected_results"]["test"]["dst_ip"] = "192.168.0.1/24"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid IP address/net:")

        self.cfg["expected_results"]["test"]["dst_ip"] = "2001:DB8::1/64"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid IP address/net:")

        self.cfg["expected_results"]["test"]["dst_ip"] = ["127.0.0.1", "2001:DB8::1"]
        self.create_monitor()
        self.verify_expres_descr("Destination IP must be in 127.0.0.1, 2001:db8::1")

        self.cfg["expected_results"]["test"]["dst_ip"] = ["192.168.0.0/24", "2001:DB8::0/64"]
        self.create_monitor()
        self.verify_expres_descr("Destination IP must fall into 192.168.0.0/24, 2001:db8::/64")

    def test_criterion_certfp(self):
        """Criterion cert_fp"""

        self.cfg["measurement-id"] = MSM_Results_SSLCert
        self.cfg["expected_results"]["test"] = {
                "cert_fp": TestMonitorCfg.FP_AAAA
        }

        self.create_monitor()
        self.verify_expres_descr("Certificate SHA256 fingerpring: AA:AA:[...]:AA:AA")

        self.cfg["expected_results"]["test"]["cert_fp"] = TestMonitorCfg.FP_AABB
        self.create_monitor()
        self.verify_expres_descr("Certificate SHA256 fingerpring: AA:AA:[...]:AA:BB")

        self.cfg["expected_results"]["test"]["cert_fp"] = [TestMonitorCfg.FP_AAAA, TestMonitorCfg.FP_AABB]
        self.create_monitor()
        self.verify_expres_descr("Certificate SHA256 fingerpring: AA:AA:[...]:AA:AA, AA:AA:[...]:AA:BB")

        self.cfg["expected_results"]["test"]["cert_fp"] = "{},{}".format(
            TestMonitorCfg.FP_AAAA, TestMonitorCfg.FP_AABB
        )
        self.create_monitor()
        self.verify_expres_descr("Certificate SHA256 fingerpring: (AA:AA:[...]:AA:AA, AA:AA:[...]:AA:BB)")

        self.cfg["expected_results"]["test"]["cert_fp"] = "aa"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid SHA256 fingerprint for cert_fp: aa")

        self.cfg["expected_results"]["test"] = {
                "cert_fp": "01:23"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid SHA256 fingerprint for cert_fp")

        self.cfg["expected_results"]["test"] = {
                "cert_fp": ""
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid SHA256 fingerprint for cert_fp")

    def test_criterion_dns_flags(self):
        """Criterion dns_flags"""

        self.cfg["measurement-id"] = MSM_Results_DNS
        self.cfg["expected_results"]["test"] = {
                "dns_flags": "AD"
        }

        self.create_monitor()
        self.verify_expres_descr("DNS response flags: ad")

        self.cfg["expected_results"]["test"]["dns_flags"] = ["ad", "rd"]
        self.create_monitor()
        self.verify_expres_descr("DNS response flags: ad, rd")

        self.cfg["expected_results"]["test"]["dns_flags"] = "xx"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid DNS flag: xx")

    def test_criterion_dns_rcode(self):
        """Criterion dns_rcode"""

        self.cfg["measurement-id"] = MSM_Results_DNS
        self.cfg["expected_results"]["test"] = {
                "dns_rcode": "NOERROR"
        }

        self.create_monitor()
        self.verify_expres_descr("DNS rcodes: NOERROR")

        self.cfg["expected_results"]["test"]["dns_rcode"] = ["NOERROR", "SERVFAIL"]
        self.create_monitor()
        self.verify_expres_descr("DNS rcodes: NOERROR, SERVFAIL")

        self.cfg["expected_results"]["test"]["dns_rcode"] = "xx"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid rcode: xx")

    def test_criterion_edns(self):
        """Criterion edns"""

        self.cfg["measurement-id"] = MSM_Results_DNS
        self.cfg["expected_results"]["test"] = {
                "edns": True
        }
        self.create_monitor()
        self.verify_expres_descr("EDNS supported")

        self.cfg["expected_results"]["test"]["edns"] = "no"
        self.create_monitor()
        self.verify_expres_descr("EDNS not supported")

        self.cfg["expected_results"]["test"]["edns"] = None

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="No criteria found.")

        self.cfg["expected_results"]["test"]["edns"] = True
        self.cfg["expected_results"]["test"]["edns_size"] = 0
        self.create_monitor()
        self.verify_expres_descr("EDNS supported; size >= 0")

        self.cfg["expected_results"]["test"]["edns_size"] = "4000"
        self.create_monitor()
        self.verify_expres_descr("EDNS supported; size >= 4000")

        self.cfg["expected_results"]["test"]["edns_size"] = "a"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'a':")

        self.cfg["expected_results"]["test"]["edns_size"] = None
        self.cfg["expected_results"]["test"]["edns_do"] = True
        self.create_monitor()
        self.verify_expres_descr("EDNS supported; DO flag on")

        self.cfg["expected_results"]["test"]["edns_do"] = "yes"
        self.create_monitor()
        self.verify_expres_descr("EDNS supported; DO flag on")

        self.cfg["expected_results"]["test"]["edns_do"] = False
        self.create_monitor()
        self.verify_expres_descr("EDNS supported; DO flag off")

        self.cfg["expected_results"]["test"]["edns_do"] = "a"
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'a':")

        del self.cfg["expected_results"]["test"]["edns_do"]
        self.cfg["expected_results"]["test"]["edns_nsid"] = "ns.example.org"
        self.create_monitor()

        self.cfg["expected_results"]["test"]["edns_nsid"] = ["ns.example.org",
                                                             "ns2.example.org"]
        self.create_monitor()

    def test_criterion_dns_answers(self):
        """Criterion dns_answers"""

        self.cfg["measurement-id"] = MSM_Results_DNS
        self.cfg["expected_results"]["test"] = {
                "dns_answers": {
                    "answers": [
                        {"type": "A", "address": "127.0.0.1"}
                    ]
                }
        }
        self.create_monitor()
        self.verify_expres_descr("answers section: A: 127.0.0.1")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "A", "address": ["127.0.0.1", "192.168.0.1"]}]
        self.create_monitor()
        self.verify_expres_descr("answers section: A: 127.0.0.1, 192.168.0.1")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "A", "address": ["127.0.0.1", "192.168.0.1"], "name": "www.example.com"}]
        self.create_monitor()
        self.verify_expres_descr("answers section: A: name www.example.com, 127.0.0.1, 192.168.0.1")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "A", "address": ["127.0.0.1", "192.168.0.1"], "name": ["www.example.com", "example.com"]}]
        self.create_monitor()
        self.verify_expres_descr("answers section: A: name in www.example.com, example.com, 127.0.0.1, 192.168.0.1")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "AAAA", "address": "127.0.0.1"}]
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid IP version")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "zzz"}]
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unhandled record type: zzz")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
                [{"type": "AAAA"}]
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Missing mandatory field: address")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "A", "address": "127.0.0.1", "aa": 1}]
        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown configuration field: aa")

        self.cfg["expected_results"]["test"]["dns_answers"]["answers"] = \
            [{"type": "NS", "target": ["test"]}]
        self.create_monitor()
        self.verify_expres_descr("answers section: NS: test")

    def test_rule(self):
        """Rule, basic tests"""

        self.cfg["matching_rules"] = [{
            "descr": "Test",
            "process_next": True,
            "src_country": "IT",
            "src_as": 12345,
            "probe_id": 1
        }]
        self.add_criterion("rtt")

        self.create_monitor()

        self.cfg["matching_rules"][0]["expected_results"] = []

        self.create_monitor()

        self.cfg["matching_rules"][0]["src_country"] = "12"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid country code: 12")

        self.cfg["matching_rules"][0]["src_as"] = "abc"

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Invalid type for 'abc':")

        self.cfg["matching_rules"][0]["unknown"] = 123

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown configuration field")

    def test_action(self):
        """Action, basic tests"""

        self.cfg["matching_rules"][0]["actions"] = "test"
        self.cfg["actions"] = {}
        self.add_criterion("rtt")

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Action not found: test")

        self.cfg["actions"]["test"] = {
            "kind": "unknown"
        }

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown action kind")

        self.cfg["actions"]["test"] = {
            "kind": "log"
        }

        self.create_monitor()

        self.cfg["actions"]["test"]["unknown"] = 123

        self.create_monitor(exp_exc=ConfigError,
                            exp_msg="Unknown configuration field")

