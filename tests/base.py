from copy import deepcopy
import mock
from time import time
import unittest
import re
import sys


from data import *
from pierky.ripeatlasmonitor.Helpers import IPCache
from pierky.ipdetailscache import IPDetailsCache
from pierky.ripeatlasmonitor.Logging import CustomLogger, LOG_LVL_RESULT
from pierky.ripeatlasmonitor.Monitor import Monitor
from ripe.atlas.cousteau import Measurement
from ripe.atlas.cousteau.request import AtlasLatestRequest, AtlasRequest


log_output = ""


class TestBasicUnit(unittest.TestCase):

    def setUp(self):
        global last_msm_id
        last_msm_id = None

        self.cfg = {}

        self.debug = False

        self.ip_cache_mocked = False

        def msm_fetch_meta_data(self):
            self.meta_data = deepcopy(MSMS[str(self.id)]["meta_data"])
            return True

        self.mock_msm_fetch_meta_data = mock.patch.object(
            Measurement,
            "_fetch_meta_data",
            autospec=True
        ).start()
        self.mock_msm_fetch_meta_data.side_effect = msm_fetch_meta_data

        def results_get(self):
            global last_msm_id
            last_msm_id = self.msm_id
            return True, deepcopy(MSMS[str(self.msm_id)]["results"])

        self.mock_results_get = mock.patch.object(
            AtlasLatestRequest,
            "get",
            autospec=True
        ).start()
        self.mock_results_get.side_effect = results_get

        def AtlasRequest_get(self, **kwargs):
            if "/api/v2/probes/" in self.url_path:
                return True, deepcopy(MSMS[str(last_msm_id)]["probes"])

        self.mock_probe_request = mock.patch.object(
            AtlasRequest,
            "get",
            autospec=True
        ).start()
        self.mock_probe_request.side_effect = AtlasRequest_get

        # IP Cache mocking

        self.ip_cache_mocked = True

        def ip_cache_fetch_ip(self, IP):
            return {
                "status": "unknown"
            }

        self.mock_ip_cache_fetch_ip = mock.patch.object(
            IPDetailsCache,
            "FetchIPInfo",
            autospec=True
        ).start()
        self.mock_ip_cache_fetch_ip.side_effect = ip_cache_fetch_ip

        def ip_cache_fetch_ixps(self):
            return ({}, {}, {})

        self.mock_ip_cache_fetch_ixps = mock.patch.object(
            IPDetailsCache,
            "FetchIXPsInfo",
            autospec=True
        ).start()
        self.mock_ip_cache_fetch_ixps.side_effect = ip_cache_fetch_ixps

        def ip_cache_save(self):
            return

        self.mock_ip_cache_save = mock.patch.object(
            IPCache,
            "save",
            autospec=True
        ).start()
        self.mock_ip_cache_save.side_effect = ip_cache_save

        self.ip_cache = IPCache()
        self.ip_cache.setup(
            IP_ADDRESSES_CACHE_FILE="tests/data/ip_addr.json",
            IP_PREFIXES_CACHE_FILE="tests/data/ip_pref.json",
            IXP_CACHE_FILE="tests/data/ixps.json",
            lifetime=sys.maxsize,
            use_ixps_info=True
        )

    def tearDown(self):
        mock.patch.stopall()

    def check_ip_cache_fetch_cnt(self, ip_cnt=0):
        if self.ip_cache_mocked:
            self.assertEquals(self.mock_ip_cache_fetch_ip.call_count, ip_cnt)
            self.assertEquals(self.mock_ip_cache_fetch_ixps.call_count, 0)

    def create_monitor(self, exp_exc=None, exp_msg=None):
        if exp_exc is None:
            try:
                self.created_monitor = Monitor(self.cfg, self.ip_cache)
                return self.created_monitor
            except Exception as e:
                raise
                raise self.failureException(e)
        else:
            with self.assertRaisesRegexp(exp_exc, exp_msg):
                self.created_monitor = Monitor(self.cfg, self.ip_cache)
                return self.created_monitor


class TestResultsBasicUnit(TestBasicUnit):

    def setUp(self):
        TestBasicUnit.setUp(self)

        def log(self, lvl, msg, *args, **kwargs):
            global log_output
            log_output += "\n{}".format(msg)

            global output
            if str(lvl) not in output:
                output[str(lvl)] = []
            output[str(lvl)].append(msg)

            self.logger.log(lvl, msg, *args, **kwargs)

        self.mock_log = mock.patch.object(
            CustomLogger,
            "log",
            autospec=True
        ).start()
        self.mock_log.side_effect = log

        self.monitor = None

    def run_monitor(self):
        if self.debug:
            self.cfg["matching_rules"][0]["actions"] = "Log"

        global output
        global log_output
        output = {}
        log_output = ""

        if not self.monitor:
            self.monitor = self.create_monitor()
        self.monitor.run(latest_results=True)

        self.log_output = log_output

        if self.debug:
            print(log_output)

        self.check_ip_cache_fetch_cnt()

        result_lines_cnt = 0
        ok_cnt = 0
        mismatch_cnt = 0

        self.results = []
        re_pattern = re.compile("^Rule n. (\d+)\s.+probe ID (\d+)\s.+(?:no expected result.|expected result ([^\:]+)\: (OK|MISMATCH))")
        if str(LOG_LVL_RESULT) in output:
            result_lines_cnt = len(output[str(LOG_LVL_RESULT)])

            for line in output[str(LOG_LVL_RESULT)]:
                if not line:
                    continue

                match = re_pattern.match(line)
                if match:
                    self.results.append(
                        (int(match.group(1)), int(match.group(2)), match.group(3), match.group(4))
                    )
                    if match.group(4) == "OK":
                        ok_cnt += 1
                    elif match.group(4) == "MISMATCH":
                        mismatch_cnt += 1

        return result_lines_cnt, ok_cnt, mismatch_cnt

    def process_output(self, ok, exp_cnt):
        res_cnt, ok_cnt, mismatch_cnt = self.run_monitor()

        if ok:
            self.assertEquals(ok_cnt, exp_cnt)
            self.assertEquals(mismatch_cnt, 0)
        else:
            self.assertEquals(mismatch_cnt, exp_cnt)
            self.assertEquals(ok_cnt, 0)
