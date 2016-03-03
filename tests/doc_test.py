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

import unittest

import yaml
from pierky.ripeatlasmonitor.doc import build_monitor_cfg_tpl, build_doc

class TestDocUnit(unittest.TestCase):

    def test_build_doc(self):
        """Doc, .rst from docstrings"""

        try:
            build_doc()
        except Exception as e:
            raise self.failureException(e)

    def test_commented_monitor_cfg_tpl(self):
        """Doc, monitor configuration template (commented)"""

        try:
            r = build_monitor_cfg_tpl(comment_optional=True)
        except Exception as e:
            raise self.failureException(e)

        cfg = yaml.load(r)

        self.assertIsInstance(cfg, dict)

        self.assertIn("matching_rules", cfg)
        self.assertIsInstance(cfg["matching_rules"], list)

    def test_monitor_cfg_tpl(self):
        """Doc, monitor configuration template"""

        try:
            r = build_monitor_cfg_tpl(comment_optional=False)
        except Exception as e:
            raise self.failureException(e)

        cfg = yaml.load(r)

        self.assertIsInstance(cfg, dict)

        self.assertIn("matching_rules", cfg)
        self.assertIsInstance(cfg["matching_rules"], list)

        self.assertIn("expected_results", cfg)
        self.assertIsInstance(cfg["expected_results"], dict)

        self.assertIn("actions", cfg)
        self.assertIsInstance(cfg["actions"], dict)

        # monitors' configuration fields that are lists
        exp_list_fields = ["matching_rules"]

        list_fields = [_ for _ in cfg if isinstance(cfg[_], list)]

        self.assertListEqual(sorted(exp_list_fields), sorted(list_fields))

        for _ in exp_list_fields:
            self.assertEqual(len(cfg[_]), 2)

        self.assertEqual(len(cfg["expected_results"].keys()), 2)

        self.assertEqual(len(cfg["actions"].keys()), 2)

        for rule in cfg["matching_rules"]:
            self.assertIsInstance(rule, dict)
            self.assertIn("expected_results", rule)
            self.assertIsInstance(rule["expected_results"], list)

            self.assertIn("actions", rule)
            self.assertIsInstance(rule["actions"], list)

            # rules configuration fields that are lists
            exp_list_fields = ["src_country", "src_as", "probe_id",
                               "internal_labels", "expected_results",
                               "actions"]

            list_fields = [_ for _ in rule if isinstance(rule[_], list)]

            self.assertListEqual(sorted(exp_list_fields), sorted(list_fields))

            for _ in exp_list_fields:
                self.assertEqual(len(rule[_]), 3)

        for expres in cfg["expected_results"].keys():
            self.assertIsInstance(cfg["expected_results"][expres], dict)
            expres = cfg["expected_results"][expres]

            # expected results' configuration fields that are lists
            exp_list_fields = ["dst_ip", "dst_as", "as_path", "upstream_as",
                               "cert_fp", "dns_rcode", "dns_flags", "edns_nsid"]

            list_fields = [_ for _ in expres if isinstance(expres[_], list)]

            self.assertListEqual(sorted(exp_list_fields), sorted(list_fields))

            for _ in exp_list_fields:
                self.assertEqual(len(expres[_]), 3)

            self.assertIsInstance(expres["dns_answers"], dict)

            dns_answers = expres["dns_answers"]

            for dns_section in dns_answers:
                dns_section = dns_answers[dns_section]
                self.assertIsInstance(dns_section, list)

                for record in dns_section:
                    # expected results' configuration fields that are lists
                    exp_list_fields = ["name", "address", "target"]

                    list_fields = [_ for _ in record if isinstance(record[_], list)]

                    self.assertListEqual(sorted(exp_list_fields), sorted(list_fields))

        for action in cfg["actions"].keys():
            self.assertIsInstance(cfg["actions"][action], dict)
