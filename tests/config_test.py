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
