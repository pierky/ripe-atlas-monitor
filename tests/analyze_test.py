from .base import TestBasicUnit
from .data import MSM_Results_Traceroute_IPv4, MSM_Results_Ping_IPv4, \
                  MSM_Results_SSLCert, MSM_Results_DNS


class TestAnalyze(TestBasicUnit):

    def setUp(self):
        TestBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [],
            "measurement-id": 0
        }
        self.maxDiff = None

    def analyze(self):
        monitor = self.create_monitor()
        return monitor.analyze()

    def equal(self, a, b):
        a = "\n".join([line.strip() for line in a.split("\n") if line])
        b = "\n".join([line.strip() for line in b.split("\n") if line])
        self.assertGreater(len(a), 0)
        self.assertEqual(a, b)

    def test_traceroute_msm(self):
        """Analyze, traceroute"""

        self.cfg["measurement-id"] = MSM_Results_Traceroute_IPv4
        r = self.analyze()

        exp_r = """Unique median RTTs:

   98.34 ms, probe ID 12527 (AS25309, IT)

  100.62 ms, probe ID 12120 (AS137, IT)

  105.16 ms, probe ID 738 (AS39759, IT)

  105.64 ms, probe ID 24535 (AS60049, IT)

  112.69 ms, probe ID 713 (AS20912, IT)

  116.87 ms, probe ID 11821 (AS49360, IT)

  181.18 ms, probe ID 832 (AS21034, IT)

Destination responded:

 yes: 7 times, probe ID 713 (AS20912, IT), probe ID 738 (AS39759, IT), probe ID 832 (AS21034, IT), ...

  no: 1 time, probe ID 24503 (AS12363, IT)

Unique destination IP addresses:

 66.220.156.68: 8 times, probe ID 713 (AS20912, IT), probe ID 738 (AS39759, IT), probe ID 832 (AS21034, IT), ...

Destination AS:

 32934: 7 times, probe ID 713 (AS20912, IT), probe ID 738 (AS39759, IT), probe ID 832 (AS21034, IT), ...

 12363: 1 time, probe ID 24503 (AS12363, IT)

Upstream AS:

  8928: 1 time, probe ID 832 (AS21034, IT)

 60049: 1 time, probe ID 24535 (AS60049, IT)

 49360: 1 time, probe ID 11821 (AS49360, IT)

 25309: 1 time, probe ID 12527 (AS25309, IT)

   137: 1 time, probe ID 12120 (AS137, IT)

  1267: 1 time, probe ID 738 (AS39759, IT)

  1200: 1 time, probe ID 713 (AS20912, IT)

Unique AS path:

              S 32934: 2 times, probe ID 12120 (AS137, IT), probe ID 12527 (AS25309, IT)

         S 8928 32934: 1 time, probe ID 832 (AS21034, IT)

 S 5602 32934 S 32934: 1 time, probe ID 24535 (AS60049, IT)

         S 1267 32934: 1 time, probe ID 738 (AS39759, IT)

    S 1267 1200 32934: 1 time, probe ID 713 (AS20912, IT)

 S 1200 32934 S 32934: 1 time, probe ID 11821 (AS49360, IT)

                    S: 1 time, probe ID 24503 (AS12363, IT)

Unique AS path (with IXPs networks):

              S IX 32934: 2 times, probe ID 12120 (AS137, IT), probe ID 12527 (AS25309, IT)

            S 8928 32934: 1 time, probe ID 832 (AS21034, IT)

 S 5602 IX 32934 S 32934: 1 time, probe ID 24535 (AS60049, IT)

         S 1267 IX 32934: 1 time, probe ID 738 (AS39759, IT)

       S 1267 1200 32934: 1 time, probe ID 713 (AS20912, IT)

    S 1200 32934 S 32934: 1 time, probe ID 11821 (AS49360, IT)

                       S: 1 time, probe ID 24503 (AS12363, IT)"""

        self.equal(r, exp_r)

    def test_ping_msm(self):
        """Analyze, ping"""

        self.cfg["measurement-id"] = MSM_Results_Ping_IPv4
        r = self.analyze()

        exp_r = """Unique median RTTs:

   14.32 ms, probe ID 13939 (AS51862, DE) 

   29.61 ms, probe ID 10025 (AS44574, GB)

   30.51 ms, probe ID 3207 (AS29562, DE)

   34.26 ms, probe ID 3183 (AS16097, DE)

   37.42 ms, probe ID 11421 (AS3209, DE)

Destination responded:

 yes: 5 times, probe ID 3183 (AS16097, DE), probe ID 3207 (AS29562, DE), probe ID 10025 (AS44574, GB), ...

Unique destination IP addresses:

 193.170.114.242: 5 times, probe ID 3183 (AS16097, DE), probe ID 3207 (AS29562, DE), probe ID 10025 (AS44574, GB), ..."""

        self.equal(r, exp_r)

    def test_ssl_msm(self):
        """Analyze, ssl"""

        self.cfg["measurement-id"] = MSM_Results_SSLCert
        r = self.analyze()

        exp_r = """Unique destination IP addresses:

    38.229.72.16: 2 times, probe ID 1000 (AS4804, AU), probe ID 10095 (AS18199, NZ)

     86.59.30.40: 1 time, probe ID 10099 (AS7922, US)

   67.215.65.130: 1 time, probe ID 12443 (AS6079, US)

    38.229.72.14: 1 time, probe ID 10082 (AS9198, KZ)

 204.194.238.143: 1 time, probe ID 12318 (AS20115, US)

Unique SSL certificate fingerprints:

 21:EB:37:AB:4C:F6:EF:89:65:EC:17:66:40:9C:A7:6B:8B:2E:03:F2:D1:A3:88:DF:73:42:08:E8:6D:EE:E6:79,
 36:13:D2:B2:2A:75:00:94:76:0C:41:AD:19:DB:52:A4:F0:5B:DE:A8:01:72:E2:57:87:61:AD:96:7F:7E:D9:AA: 4 times, probe ID 1000 (AS4804, AU), probe ID 10082 (AS9198, KZ), probe ID 10095 (AS18199, NZ), ...

 6D:5B:C9:79:46:1C:72:64:E1:71:00:10:CD:7D:4E:A3:EC:57:FA:11:21:5F:04:FF:A5:16:AE:61:95:9A:B2:B2,
 BE:9E:83:54:86:12:70:4C:E3:18:7F:E4:53:F8:73:B2:05:B3:9D:7B:4E:7C:19:A9:05:27:B7:4E:05:F3:9E:5F: 2 times, probe ID 12318 (AS20115, US), probe ID 12443 (AS6079, US)"""

        self.equal(r, exp_r)

    def test_dns_msm(self):
        """Analyze, dns"""

        self.cfg["measurement-id"] = MSM_Results_DNS
        r = self.analyze()

        exp_r = """Unique DNS flags combinations:

     qr, ra, rd: 2 times, probe ID 11891 (AS22795, US), probe ID 12320 (AS22773, US)

 ad, qr, ra, rd: 1 time, probe ID 10080 (AS4713, JP)

EDNS present:

 yes: 3 times, probe ID 10080 (AS4713, JP), probe ID 11891 (AS22795, US), probe ID 12320 (AS22773, US)

EDNS size:

 4096: 2 times, probe ID 11891 (AS22795, US), probe ID 12320 (AS22773, US)

  512: 1 time, probe ID 10080 (AS4713, JP)

EDNS DO flag:

 yes: 3 times, probe ID 10080 (AS4713, JP), probe ID 11891 (AS22795, US), probe ID 12320 (AS22773, US)"""
        self.equal(r, exp_r)
