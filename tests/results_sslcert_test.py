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
from .data import MSM_Results_SSLCert
from pierky.ripeatlasmonitor.Monitor import Monitor


class TestSSLCertResult(TestResultsBasicUnit):

    def setUp(self):
        TestResultsBasicUnit.setUp(self)

        FP_VALID_LEAF = "36:13:D2:B2:2A:75:00:94:76:0C:41:AD:19:DB:52:A4:F0:5B:DE:A8:01:72:E2:57:87:61:AD:96:7F:7E:D9:AA"
        FP_VALID_ISSUER = "21:EB:37:AB:4C:F6:EF:89:65:EC:17:66:40:9C:A7:6B:8B:2E:03:F2:D1:A3:88:DF:73:42:08:E8:6D:EE:E6:79"
        FP_INVALID = "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"

        # 6 total probes in msm MSM_Results_SSLCert
        # - 4 see FP_VALID_LEAF and FP_VALID_ISSUER (ID 1000, 10082, 10095,
        #   10099)
        # - 2 see other fingerprints (ID 12318, 12443)

        self.cfg = {
            "matching_rules": [
                {
                    "expected_results": [],
                    "actions": []
                }
            ],
            "expected_results": {
                "DestinationResponded": {
                    "dst_responded": True
                },
                "Valid_Leaf": {
                    "cert_fp": FP_VALID_LEAF
                },
                "Valid_Issuer": {
                    "cert_fp": FP_VALID_ISSUER
                },
                "Valid_LeafIssuerBundle": {
                    "cert_fp": "{},{}".format(FP_VALID_LEAF, FP_VALID_ISSUER)
                },
                "Valid_IssuerLeafBundle": {
                    "cert_fp": "{},{}".format(FP_VALID_ISSUER, FP_VALID_LEAF)
                },
                "Invalid": {
                    "cert_fp": FP_INVALID
                },
                "Valid_Leaf_Invalid": {
                    "cert_fp": [FP_VALID_LEAF, FP_INVALID]
                },
                "Invalid_Bundle1": {
                    "cert_fp": "{},{}".format(FP_VALID_LEAF, FP_INVALID)
                },
                "Invalid_Bundle2": {
                    "cert_fp": "{},{},{}".format(FP_VALID_LEAF,
                                                 FP_VALID_ISSUER, FP_INVALID)
                }
            },
            "actions": {
                "Log": {
                    "kind": "log"
                }
            },
            "measurement-id": MSM_Results_SSLCert
        }

    def test_valid_leaf(self):
        """SSLCert, valid leaf"""

        self.cfg["matching_rules"][0]["probe_id"] = [1000, 10082, 10095, 10099]
        self.cfg["matching_rules"][0]["expected_results"] = ["Valid_Leaf"]

        self.process_output(True, 4)

    def test_valid_issuer(self):
        """SSLCert, valid issuer"""

        self.cfg["matching_rules"][0]["probe_id"] = [1000, 10082, 10095, 10099]
        self.cfg["matching_rules"][0]["expected_results"] = ["Valid_Issuer"]

        self.process_output(True, 4)

    def test_valid_leaf_issuer_bundle(self):
        """SSLCert, valid leaf+issuer bundle"""

        self.cfg["matching_rules"][0]["probe_id"] = [1000, 10082, 10095, 10099]
        self.cfg["matching_rules"][0]["expected_results"] = \
            ["Valid_LeafIssuerBundle"]

        self.process_output(True, 4)

    def test_valid_issuer_leaf_bundle(self):
        """SSLCert, valid issuer + leaf bundle"""

        self.cfg["matching_rules"][0]["probe_id"] = [1000, 10082, 10095, 10099]
        self.cfg["matching_rules"][0]["expected_results"] = \
            ["Valid_IssuerLeafBundle"]

        self.process_output(True, 4)

    def test_invalid(self):
        """SSLCert, invalid"""

        self.cfg["matching_rules"][0]["expected_results"] = ["Invalid"]

        self.process_output(False, 6)

    def test_valid_leaf_invalid(self):
        """SSLCert, valid leaf + invalid"""

        self.cfg["matching_rules"][0]["probe_id"] = [1000, 10082, 10095, 10099]
        self.cfg["matching_rules"][0]["expected_results"] = \
            ["Valid_Leaf_Invalid"]

        self.process_output(True, 4)

    def test_invalid_bundle1(self):
        """SSLCert, invalid bundle"""

        self.cfg["matching_rules"][0]["expected_results"] = ["Invalid_Bundle1"]

        self.process_output(False, 6)

    def test_invalid_bundle2(self):
        """SSLCert, invalid bundle (valid bundle extended with invalid cert)"""

        self.cfg["matching_rules"][0]["expected_results"] = ["Invalid_Bundle2"]

        self.process_output(False, 6)

    def test_dest_responded(self):
        """SSLCert, destination responded"""

        self.cfg["matching_rules"][0]["expected_results"] = "DestinationResponded"
        self.process_output(True, 6)
