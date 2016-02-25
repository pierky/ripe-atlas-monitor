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


from pierky.ripeatlasmonitor.Config import Config
from pierky.ripeatlasmonitor.Errors import GlobalConfigError


class TestConfig(unittest.TestCase):

    def test_basic(self):
        """Configuration, basic test"""
        Config.parse({
            "ip_cache": {
                "dir": "test"
            }
        })

        self.assertEquals(
            Config.get("ip_cache.dir"),
            "test"
        )

    def test_unknown_param(self):
        """Configuration, unknown parameter"""
        
        with self.assertRaisesRegexp(GlobalConfigError, "unknown parameter"):
            Config.parse({
                "bad": 1
            })

    def test_wrong_type(self):
        """Configuration, wrong type"""

        with self.assertRaisesRegexp(GlobalConfigError, "invalid type for dir"):
            Config.parse({
                "ip_cache": {
                    "dir": 1
                }
            })
