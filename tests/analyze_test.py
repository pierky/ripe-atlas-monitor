from base import TestBasicUnit
from data import MSM_Results_Traceroute_IPv4, MSM_Results_Ping_IPv4, \
                 MSM_Results_SSLCert, MSM_Results_DNS


class TestAnalyze(TestBasicUnit):

    def setUp(self):
        TestBasicUnit.setUp(self)

        self.cfg = {
            "matching_rules": [],
            "measurement-id": 0
        }

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

        exp_r = """Median RTTs:

   98.34 ms

  100.62 ms

  105.16 ms

  105.64 ms

  112.69 ms

  116.87 ms

  181.18 ms

       none

Destination responded:

 yes: 7 times

  no: 1 time

Unique destination IP addresses:

 66.220.156.68: 8 times

Unique AS path:

 49360 1200 32934 49360 32934: 1 time

        20912 1267 1200 32934: 1 time

                        12363: 1 time

                    137 32934: 1 time

                  25309 32934: 1 time

             39759 1267 32934: 1 time

 60049 5602 32934 60049 32934: 1 time

             21034 8928 32934: 1 time

Unique AS path (with IXPs networks):

    49360 1200 32934 49360 32934: 1 time

           20912 1267 1200 32934: 1 time

                           12363: 1 time

 60049 5602 IX 32934 60049 32934: 1 time

                    137 IX 32934: 1 time

             39759 1267 IX 32934: 1 time

                  25309 IX 32934: 1 time

                21034 8928 32934: 1 time"""

#        self.equal(r, exp_r)

    def test_ping_msm(self):
        """Analyze, ping"""

        self.cfg["measurement-id"] = MSM_Results_Ping_IPv4
        r = self.analyze()

        exp_r = """Median RTTs:

   14.32 ms

   29.61 ms

   30.51 ms

   34.26 ms

   37.42 ms

Destination responded:

 yes: 5 times

Unique destination IP addresses:

 193.170.114.242: 5 times"""

        self.equal(r, exp_r)

    def test_ssl_msm(self):
        """Analyze, ssl"""

        self.cfg["measurement-id"] = MSM_Results_SSLCert
        r = self.analyze()

        exp_r = """Unique destination IP addresses:

    38.229.72.16: 2 times

    38.229.72.14: 1 time

     86.59.30.40: 1 time

 204.194.238.143: 1 time

   67.215.65.130: 1 time

Unique SSL certificate fingerprints:

 21:EB:37:AB:4C:F6:EF:89:65:EC:17:66:40:9C:A7:6B:8B:2E:03:F2:D1:A3:88:DF:73:42:08:E8:6D:EE:E6:79,
 36:13:D2:B2:2A:75:00:94:76:0C:41:AD:19:DB:52:A4:F0:5B:DE:A8:01:72:E2:57:87:61:AD:96:7F:7E:D9:AA: 4 times

 6D:5B:C9:79:46:1C:72:64:E1:71:00:10:CD:7D:4E:A3:EC:57:FA:11:21:5F:04:FF:A5:16:AE:61:95:9A:B2:B2,
 BE:9E:83:54:86:12:70:4C:E3:18:7F:E4:53:F8:73:B2:05:B3:9D:7B:4E:7C:19:A9:05:27:B7:4E:05:F3:9E:5F: 2 times"""

#        self.equal(r, exp_r)

    def test_dns_msm(self):
        """Analyze, dns"""

        self.cfg["measurement-id"] = MSM_Results_DNS
        r = self.analyze()

        exp_r = """Unique DNS flags combinations:

     rd, qr, ra: 2 times

 rd, qr, ad, ra: 1 time

EDNS present:

 yes: 3 times

EDNS size:

 4096: 2 times

  512: 1 time

EDNS DO flag:

 yes: 3 times"""

#        self.equal(r, exp_r)
