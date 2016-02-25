from .base import TestBasicUnit
from .data import MSM_Results_Traceroute_IPv4, MSM_Results_Ping_IPv4, \
                  MSM_Results_SSLCert, MSM_Results_DNS, \
                  MSM_Results_Traceroute_Big
from pierky.ripeatlasmonitor.Analyzer import Analyzer


class TestAnalyze(TestBasicUnit):

    def load_analyze_results(self, msm_id, tag=None):
        path = "tests/data/{}{}.analyze".format(
            msm_id, "_" + tag if tag else "")

        with open(path, "r") as f:
            s = f.read()
        self.exp_res = s

    def setUp(self):
        TestBasicUnit.setUp(self)

        self.msm_id = 0
        self.exp_res = None
        self.maxDiff = None

    def analyze(self, *args, **kwargs):
        if self.exp_res is None:
            self.load_analyze_results(self.msm_id)

        analyzer = Analyzer(ip_cache=self.ip_cache, msm_id=self.msm_id)

        r = analyzer.analyze(*args, **kwargs)

        if self.debug:
            print(r)
            return

        self.equal(r, self.exp_res)

    def equal(self, a, b):
        a = "\n".join([line.strip() for line in a.split("\n") if line])
        b = "\n".join([line.strip() for line in b.split("\n") if line])
        self.assertGreater(len(a), 0)
        self.assertEqual(a, b)

    def test_traceroute_msm(self):
        """Analyze, traceroute"""

        self.msm_id = MSM_Results_Traceroute_IPv4
        self.analyze()

    def test_ping_msm(self):
        """Analyze, ping"""

        self.msm_id = MSM_Results_Ping_IPv4
        self.analyze()

    def test_ssl_msm(self):
        """Analyze, ssl"""

        self.msm_id = MSM_Results_SSLCert
        self.analyze()

    def test_dns_msm(self):
        """Analyze, dns"""

        self.msm_id = MSM_Results_DNS
        self.analyze()

    def test_msm_stats(self):
        """Analyze, stats"""

        self.msm_id = MSM_Results_SSLCert
        self.load_analyze_results(self.msm_id)
        self.exp_res += """\nStatistics:

 - 6 unique probes found
 - countries with more than 1 probe:
   - US: 3 probes
 - no source ASNs with more than 1 probe

Analyzing results from US (3 probes)...

Unique destination IP addresses:

     86.59.30.40: 1 time, probe ID 10099 (AS7922, US)

   67.215.65.130: 1 time, probe ID 12443 (AS6079, US)

 204.194.238.143: 1 time, probe ID 12318 (AS20115, US)

Unique SSL certificate fingerprints:

 6D:5B:C9:79:46:1C:72:64:E1:71:00:10:CD:7D:4E:A3:EC:57:FA:11:21:5F:04:FF:A5:16:AE:61:95:9A:B2:B2,
 BE:9E:83:54:86:12:70:4C:E3:18:7F:E4:53:F8:73:B2:05:B3:9D:7B:4E:7C:19:A9:05:27:B7:4E:05:F3:9E:5F: 2 times, probe ID 12318 (AS20115, US), probe ID 12443 (AS6079, US)

 21:EB:37:AB:4C:F6:EF:89:65:EC:17:66:40:9C:A7:6B:8B:2E:03:F2:D1:A3:88:DF:73:42:08:E8:6D:EE:E6:79,
 36:13:D2:B2:2A:75:00:94:76:0C:41:AD:19:DB:52:A4:F0:5B:DE:A8:01:72:E2:57:87:61:AD:96:7F:7E:D9:AA: 1 time, probe ID 10099 (AS7922, US)"""

        self.analyze(show_stats=True, cc_threshold=1, top_countries=10,
                     as_threshold=1, top_asns=10)

    def test_traceroute_big_msm(self):
        """Analyze, traceroute (big)"""

        self.msm_id = MSM_Results_Traceroute_Big
        self.analyze()

    def test_traceroute_big_msm_stats(self):
        """Analyze, traceroute (big) with stats"""

        self.msm_id = MSM_Results_Traceroute_Big
        self.load_analyze_results(self.msm_id)
        self.exp_res += """\nStatistics:

 - 87 unique probes found
 - countries with more than 1 probe:
   - DE: 15 probes
   - NL: 14 probes
   - GB: 13 probes
   - RU: 7 probes
   - FI: 4 probes
   - FR: 4 probes
   - AT: 3 probes
   - BE: 3 probes
   - SE: 3 probes
   - UA: 3 probes
   - CH: 2 probes
   - CZ: 2 probes
   - IT: 2 probes
   - NO: 2 probes
   - PL: 2 probes
 - source ASNs with more than 1 probe:
   -    6830: 6 probes
   -    3209: 2 probes
   -    3265: 2 probes
   -    3320: 2 probes
   -    6848: 2 probes
   -    9143: 2 probes
   -   12871: 2 probes
   -   31334: 2 probes"""

        self.analyze(show_stats=True,
                     cc_threshold=1,
                     as_threshold=1)

    def test_traceroute_big_msm_show_all_dstas(self):
        """Analyze, traceroute (big), show all dst as"""

        self.msm_id = MSM_Results_Traceroute_Big
        self.load_analyze_results(self.msm_id, tag="all_dstas")
        self.analyze(show_full_destasn=True)

    def test_traceroute_big_msm_show_all_upstreamas(self):
        """Analyze, traceroute (big), show all upstream as"""

        self.msm_id = MSM_Results_Traceroute_Big
        self.load_analyze_results(self.msm_id, tag="all_upstreamas")
        self.analyze(show_full_upstreamasn=True)

    def test_traceroute_big_msm_show_all_rtt(self):
        """Analyze, traceroute (big), show all rtt"""

        self.msm_id = MSM_Results_Traceroute_Big
        self.load_analyze_results(self.msm_id, tag="all_rtt")
        self.analyze(show_full_rtts=True)

    def test_traceroute_big_msm_show_all_aspath(self):
        """Analyze, traceroute (big), show all as path"""

        self.msm_id = MSM_Results_Traceroute_Big
        self.load_analyze_results(self.msm_id, tag="all_aspath")
        self.analyze(show_full_aspaths=True)
