from .base import TestBasicUnit
from .data import *
from pierky.ripeatlasmonitor.Monitor import Monitor

class TestIPCache(TestBasicUnit):

    def setUp(self):
        TestBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [{"expected_results": []}],
            "expected_results": {},
            "measurement-id": MSM_Ping_IPv6_Stopped
        }

    def test_cached_ip(self):
        """IP cache, cached IP"""
        monitor = Monitor(self.cfg, self.ip_cache)

        # "173.252.65.52" is one of the IP addresses in the cache
        ip_info = self.ip_cache.get_ip_info("173.252.65.52")

        self.check_ip_cache_fetch_cnt()
        self.assertEquals(ip_info["ASN"], "32934")

    def test_cached_prefix(self):
        """IP cache, cached prefix"""
        monitor = Monitor(self.cfg, self.ip_cache)

        # "173.252.65.53" is not in the IP addresses cache, but matches the
        # prefix of the previous one
        ip_info = self.ip_cache.get_ip_info("173.252.65.53")

        self.check_ip_cache_fetch_cnt()
        self.assertEquals(ip_info["ASN"], "32934")

    def test_missing_ip(self):
        """IP cache, missing IP"""
        monitor = Monitor(self.cfg, self.ip_cache)

        # "193.0.6.139" is not in the cache at all
        ip_info = self.ip_cache.get_ip_info("193.0.6.139")

        self.check_ip_cache_fetch_cnt(ip_cnt=1)

    def test_ixp_ip(self):
        """IP cache, IXP's IP"""
        monitor = Monitor(self.cfg, self.ip_cache)

        # "195.66.225.121" IP of an IXP in the cache
        ip_info = self.ip_cache.get_ip_info("195.66.225.121")

        self.check_ip_cache_fetch_cnt()
        self.assertEquals(ip_info["ASN"], "not announced")
        self.assertEquals(ip_info["IsIXP"], True)
        self.assertEquals(ip_info["IXPName"], "LINX Juniper LAN")

