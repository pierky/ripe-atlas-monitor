import datetime
import json
import os
from Queue import Queue, Empty
import time
from threading import Thread

import pytz
import yaml

from Action import ACTION_CLASSES
from Config import Config
from Errors import ConfigError, MissingFileError, MeasurementProcessingError, \
                   LockError, ProgramError, ResultProcessingError
from ExpectedResult import ExpectedResult
from Helpers import BasicConfigElement, Probe, LockFile
from Logging import logger
from ripe.atlas.cousteau import AtlasResultsRequest, AtlasLatestRequest, \
                                ProbeRequest, AtlasStream, Measurement
from ripe.atlas.cousteau.exceptions import CousteauGenericError, \
                                           APIResponseError
from ripe.atlas.sagan import Result
from Rule import Rule


class MonitorResultsThread(Thread):
    def __init__(self, monitor):
        Thread.__init__(self)
        self.monitor = monitor

    def run(self):
        while not self.monitor.exit_thread:
            try:
                result = self.monitor.results_queue.get(True, 1)
                self.monitor.process_results([result])
            except Empty:
                pass


class Monitor(BasicConfigElement):
    """Monitor

    A monitor allows to process results from a measurement.

    `descr` (optional): monitor's brief description.

    `measurement-id` (optional): measurement ID used to gather results. It can
    be given (and/or overwritten) via command line argument `--measurement-id`.

    `matching_rules`: list of rules to match probes against. When a probe
    matches one of these rules, its expected results are processed and its
    actions are performed.

    `expected_results` (optional): list of expected results. Probe's expected
    results contain references to this list.

    `actions` (optional): list of actions to be executed on the basis of
    probe's expected results.

    `stream` (optional): boolean indicating if results streaming must be used.
    It can be given (and/or overwritten) via command line argument `--stream`.

    `stream_timeout` (optional): how long to wait (in seconds) before stopping
    a streaming monitor if no results are received on the stream.

    `key` (optional): RIPE Atlas key to access the measurement. It can be
    given (and/or overwritten) via command line argument `--key`.

    `key_file` (optional): a file containing the RIPE Atlas key to access the
    measurement. The file must contain only the RIPE Atlas key, in plain text.
    If `key` is given, this field is ignored.
    """

    MANDATORY_CFG_FIELDS = ["matching_rules"]

    OPTIONAL_CFG_FIELDS = ["measurement-id", "stream", "stream_timeout",
                           "actions", "key", "key_file", "descr",
                           "expected_results"]

    @staticmethod
    def _load_msm(id=None, key=None):
        try:
            return Measurement(id=id, key=key)
        except (CousteauGenericError, APIResponseError) as e:
            raise MeasurementProcessingError(
                "Error while retrieving measurement details: {}".format(
                    repr(e)
                )
            )

    def _get_statusfile_path(self):
        if self.monitor_name:
            return "{}/status/{}.{}.json".format(
                Config.get("var_dir"),
                self.monitor_name,
                self.msm_id
            )
        return None

    def _get_lockfile_path(self):
        if self.monitor_name:
            return "{}/locks/{}.{}.lock".format(
                Config.get("var_dir"),
                self.monitor_name,
                self.msm_id
            )
        return None

    def _load_from_file(self, monitor_name):
        file_path = "{}/monitors/{}.yaml".format(
            Config.get("var_dir"), monitor_name
        )

        if not os.path.isfile(file_path):
            raise MissingFileError(path=file_path)

        try:
            with open(file_path, "r") as monitor_file:
                try:
                    return yaml.load(monitor_file.read())
                except yaml.parser.ParserError as e:
                    raise ConfigError(
                        "Error in YAML syntax: {}".format(str(e))
                    )
        except Exception as e:
            raise ConfigError(
                "Can't read from the monitor configuration file {}: {}".format(
                    file_path, str(e)
                )
            )

    def __init__(self, cfg_or_name, ip_cache=None, msm_id=None, key=None):

        if isinstance(cfg_or_name, str):
            self.monitor_name = cfg_or_name
            cfg = self._load_from_file(self.monitor_name)

        elif isinstance(cfg_or_name, dict):
            self.monitor_name = None
            cfg = cfg_or_name

        else:
            raise ConfigError(
                "Invalid monitor name or configuration type: {}".format(
                    type(cfg_or_name)
                )
            )

        self.ip_cache = ip_cache

        BasicConfigElement.__init__(self, cfg)

        self.normalize_fields()

        self.descr = self._enforce_param("descr", str)

        self._enforce_param("matching_rules", list)

        self._enforce_param("expected_results", dict) or {}

        self._enforce_param("actions", dict)

        self.msm_id = msm_id or self._enforce_param("measurement-id", int)

        if self.msm_id is None:
            raise ConfigError(
                "Missing measurement ID: it must be specified in the "
                "monitor configuration file or provided using the "
                "command line argument --measurement-id."
            )

        self.key = key or self._enforce_param("key", str)
        self.key_file = self._enforce_param("key_file", str)

        if not self.key and self.key_file:
            if os.path.isfile(self.key_file):
                try:
                    with open(self.key_file, "r") as f:
                        self.key = f.read().rstrip()
                except Exception as e:
                    raise ConfigError(
                        "Can't read RIPE Atlas Key file {}: {}".format(
                            self.key_file, str(e)
                        )
                    )
            else:
                raise MissingFileError(self.key_file)

        self.stream = self._enforce_param("stream", bool) or False

        self.stream_timeout = self._enforce_param("stream_timeout", int)

        # Measurement validation

        msm = self._load_msm(id=self.msm_id, key=self.key)

        self.msm_type = msm.type.lower()
        self.msm_af = int(msm.protocol)
        self.msm_status = msm.status
        self.msm_status_id = msm.status_id
        self.msm_is_running = self.msm_status_id in [0, 1, 2]
        self.msm_is_oneoff = msm.is_oneoff
        self.msm_interval = msm.interval

        if self.msm_type not in ["traceroute", "ping", "sslcert", "dns"]:
            raise MeasurementProcessingError(
                "Unhandled measurement's type: "
                "{}".format(self.msm_type)
            )

        # Expected results normalization

        self.expected_results = {}

        if self.cfg["expected_results"]:
            for expres_name in self.cfg["expected_results"].keys():
                expres_cfg = self.cfg["expected_results"][expres_name]
                try:
                    expres = ExpectedResult(self, expres_name, expres_cfg)
                    self.expected_results[expres_name] = expres
                except ConfigError as e:
                    raise ConfigError(
                        "Syntax error for expected result {} - {}".format(
                            expres_name, str(e)
                        )
                    )

        # Actions normalization

        self.actions = {}

        if self.cfg["actions"]:
            for action_name in self.cfg["actions"].keys():
                action_cfg = self.cfg["actions"][action_name]
                try:
                    if "kind" in action_cfg:
                        action_kind = action_cfg["kind"]
                        action = None

                        for action_class in ACTION_CLASSES:
                            if action_class.CFG_ACTION_KIND == action_kind:
                                action = action_class(self, action_name,
                                                      action_cfg)
                                break

                        if action is None:
                            raise ConfigError(
                                "Unknown action kind: {}".format(
                                    action_kind
                                )
                            )

                        self.actions[action_name] = action
                    else:
                        raise ConfigError("Missing action kind")
                except ConfigError as e:
                    raise ConfigError(
                        "Syntax error for action {} - {}".format(
                            action_name, str(e)
                        )
                    )

        # Rules normalization

        self.rules = []

        rule_n = 0
        for rule_cfg in self.cfg["matching_rules"]:
            rule_n += 1

            try:
                rule = Rule(self, rule_cfg)
                self.rules.append(rule)

                if rule.expected_results and rule.expected_results != []:
                    for expres_name in rule.expected_results:
                        if expres_name not in self.expected_results:
                            raise ConfigError(
                                "Expected result not found: "
                                "{}".format(expres_name)
                            )

                if rule.actions and rule.actions != []:
                    for action_name in rule.actions:
                        if action_name not in self.actions.keys():
                            raise ConfigError(
                                "Action not found: "
                                "{}".format(action_name)
                            )

            except ConfigError as e:
                raise ConfigError(
                    "Syntax error for rule n. {} - {}".format(
                        rule_n, str(e)
                    )
                )

        # dictionary of "<probe_id>": "<json>"
        #   where <json> = https://atlas.ripe.net/docs/rest/#probe
        self.probes = {}      # TODO: add a cache for probes

        # Used by ExpResCriterion [get|set]_parsed_res.
        # ExpResCriterion objects use this dictionary as
        # a cache when they parse results and transform
        # them in a way they can subsequently understand.
        # Multiple criteria for the same ExpectedResult
        # can parse results only once and store here the
        # data they need for the result_matches method.
        self.parsed_res = {}

        self.internal_labels = {
            "probes": {},
            "results": {}
        }

        self.exit_thread = False
        self.results_queue = None

        self.lock_fd = None
        self.lock_file = LockFile()

        self.status = {}
        self.load_status()
        self._epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)

    def load_status(self):
        status_filepath = self._get_statusfile_path()
        if status_filepath:
            if os.path.isfile(status_filepath):
                try:
                    with open(status_filepath, "r") as f:
                        self.status = json.loads(f.read())
                except:
                    raise ProgramError(
                        "Can't read status from {}".format(status_filepath)
                    )

    def write_status(self):
        status_filepath = self._get_statusfile_path()
        if status_filepath:
            try:
                with open("{}.tmp".format(status_filepath), "w") as f:
                    f.write(json.dumps(self.status))
                os.rename("{}.tmp".format(status_filepath), status_filepath)
            except:
                raise ProgramError(
                    "Can't write status to {}".format(status_filepath)
                )

    def __str__(self):
        if self.descr:
            return "monitor '{}'".format(self.descr)
        else:
            if self.monitor_name:
                tpl = ("monitor '{name}' "
                       "(measurement ID {msm_id}, {msm_type}, IPv{af})")
            else:
                tpl = ("monitor for measurement ID {msm_id} "
                       "({msm_type}, IPv{af})")

            return tpl.format(
                name=self.monitor_name,
                msm_id=self.msm_id,
                msm_type=self.msm_type,
                af=self.msm_af
            )

    def display(self):
        if self.msm_id:
            print("Measurement ID: {}".format(self.msm_id))
        else:
            print(
                "Measurement ID not specified, it must be given using the "
                "command line argument --measurement-id."
            )
        print("")

        if self.stream:
            if self.stream_timeout:
                print("Streaming of results enabled - "
                      "{} seconds timeout.".format(self.stream_timeout))
            else:
                print("Streaming of results enabled - no timeout.")
            print("")

        rule_n = 0
        for rule in self.rules:
            rule_n += 1

            print("Matching rule n. {}".format(rule_n))
            print("")

            rule.display()

            if len(rule.expected_results) > 0:
                print("  Expected results:")
                print("")
                for expres_name in rule.expected_results:
                    self.expected_results[expres_name].display()
            else:
                print("  No expected results for this rule.")
                print("")

            if len(rule.actions) > 0:
                print("  Actions:")
                print("")
                for action_name in rule.actions:
                    if self.actions[action_name].when == "on_match":
                        tpl = "    Action fired on match: {}"
                    elif self.actions[action_name].when == "on_mismatch":
                        tpl = "    Action fired on mismatch: {}"
                    else:
                        tpl = "    Action always fired: {}"
                    print(tpl.format(self.actions[action_name]))
                    print("")

    def get_probe(self, origin):
        if isinstance(origin, Result):
            prb_id = origin.probe_id
        elif isinstance(origin, str):
            prb_id = int(origin)
        elif isinstance(origin, int):
            prb_id = origin
        else:
            raise ResultProcessingError(
                "Unknown origin type: {}".format(type(origin))
            )

        return Probe(self.probes[str(prb_id)], self.msm_af)

    def update_probes(self, results):
        # List of probe IDs whose details must be retrieved
        unknown_probes_ids = []

        for json_result in results:
            probe_id = json_result["prb_id"]
            if str(probe_id) not in self.probes:
                # Probe never seen before, add it to the list of
                # probes to request details for
                if probe_id not in unknown_probes_ids:
                    unknown_probes_ids.append(probe_id)

        # Get details about missing probes

        if len(unknown_probes_ids) > 0:
            try:
                json_probes = ProbeRequest(id__in=unknown_probes_ids)
                for json_probe in json_probes:
                    self.probes[str(json_probe["id"])] = json_probe
            except Exception as e:
                raise ResultProcessingError(
                    "Error while retrieving probes info: {}".format(str(e))
                )

    def process_matching_probe(self, probe, rule_n, rule, result):
        logger.info("  probe ID {} matches".format(probe.id))

        if len(rule.expected_results) == 0:
            logger.result(
                "Rule n. {} ({}), {}, "
                "no expected result.".format(
                    rule_n, str(rule), probe
                )
            )
            rule.perform_actions(result=result)
            return

        for expres_name in rule.expected_results:
            expres = self.expected_results[expres_name]

            logger.info(
                "Verifying expected result {}: {}...".format(
                    expres_name, str(expres)
                )
            )

            result_matches = expres.result_matches(result)

            logger.result(
                "Rule n. {} ({}), {}, "
                "expected result {}: {}.".format(
                    rule_n, str(rule), probe, expres_name,
                    "OK" if result_matches else "MISMATCH"
                )
            )

            rule.perform_actions(result=result, expres=expres,
                                 result_matches=result_matches)

    def update_latest_result_ts(self, result):
        ts = (result.created - self._epoch).total_seconds()

        if "latest_result_ts" in self.status:
            if self.status["latest_result_ts"] > ts:
                return
        self.status["latest_result_ts"] = ts
        self.write_status()

    def process_results(self, results):
        # Be sure to have info for every probe in the resultset
        self.update_probes(results)

        if len(results) == 0:
            logger.info("No results found.")
            return

        # Processing results...

        for json_result in results:
            result = Result.get(json_result)
            self.process_result(result)
            self.update_latest_result_ts(result)
            self.internal_labels["results"] = {}

        self.ip_cache.save()

    def process_result(self, result):
        self.internal_labels["results"] = {}

        is_success = not result.is_error and not result.is_malformed

        if not is_success:
            return

        probe = self.get_probe(result)

        logger.info(
            "Processing result for {} at {}...".format(
                str(probe), result.created
            )
        )

        rule_n = 0
        for rule in self.rules:
            rule_n += 1

            logger.info(
                "Testing rule n. {}: {}...".format(rule_n, str(rule))
            )

            if rule.probe_matches(probe):
                self.process_matching_probe(probe, rule_n, rule, result)

                if rule.process_next is True:
                    logger.info("  next rule processing forcedly enabled")
                else:
                    break
            else:
                logger.info(
                    "  {} does not match".format(probe)
                )

                if rule.process_next is False:
                    logger.info("  next rule processing forcedly inhibited")
                    break

    def on_result_response(self, result):
        self.results_queue.put(result)

    def acquire_lock(self):
        if not self.monitor_name:
            return

        if not self.lock_file.acquire(self._get_lockfile_path()):
            raise LockError(
                "Another instance of this program is already "
                "executing this monitor."
            )

    def release_lock(self):
        self.lock_file.release()

    def run_stream(self):
        logger.info(" - using real-time results streaming")

        err = "Can't use results streaming for this measurement: {}"

        if self.msm_is_oneoff:
            raise MeasurementProcessingError(
                err.format("it's a one-off measurement.")
            )

        if not self.msm_is_running:
            raise MeasurementProcessingError(
                err.format("it is not running anymore.")
            )

        try:
            atlas_stream = AtlasStream()
            atlas_stream.connect()
            atlas_stream.bind_channel("result", self.on_result_response)
            stream_params = {"msm": self.msm_id}
        except Exception as e:
            raise MeasurementProcessingError(
                "Error while creating the stream: {}".format(str(e))
            )

        self.results_queue = Queue()
        thread = MonitorResultsThread(self)

        try:
            thread.start()

            atlas_stream.start_stream(stream_type="result",
                                      **stream_params)
            atlas_stream.timeout(seconds=self.stream_timeout)
            atlas_stream.disconnect()
        except:
            try:
                atlas_stream.disconnect()
            except:
                pass
        finally:
            try:
                atlas_stream.disconnect()
            except:
                pass
            self.exit_thread = True
            thread.join(timeout=10)

    def download_and_process(self, start=None, stop=None, latest_results=None):
        atlas_params = {
            "msm_id": self.msm_id,
            "key": self.key
        }

        logger.info("Downloading results...")

        if not latest_results:
            atlas_class = AtlasResultsRequest

            msm_results_days_limit = Config.get("misc.msm_results_days_limit")

            if start:
                tpl = "{start}"

            elif "latest_result_ts" in self.status:
                start = datetime.datetime.fromtimestamp(
                    self.status["latest_result_ts"]+1, tz=pytz.UTC
                )
                tpl = "{start} (last result received)"
            elif msm_results_days_limit > 0:
                start = datetime.date.today() + datetime.timedelta(
                    days=-msm_results_days_limit
                )
                tpl = ("{start} (last {limit} days on the basis of global "
                       "config msm_results_days_limit option)")
            else:
                tpl = (" - no start time given, downloading results from "
                       "the beginning of the measurement")

            logger.info(" - start time: " + tpl.format(
                start=start,
                limit=msm_results_days_limit
            ))

            if start:
                atlas_params["start"] = start

            if stop:
                tpl = "{stop}"
            else:
                tpl = (" - no stop time given, downloading results "
                       "until the last one")

            logger.info(" - stop time: " + tpl.format(stop=stop))

            if stop:
                atlas_params["stop"] = stop
        else:
            logger.info(" - retrieving latest results only")

            atlas_class = AtlasLatestRequest

        try:
            atlas_request = atlas_class(**atlas_params)

            is_success, results = atlas_request.create()

            if is_success:
                logger.info("Processing results...")
                self.process_results(results)
            else:
                err = str(results)
                if isinstance(results, dict):
                    if "detail" in results:
                        err = results["detail"]
                    elif "error" in results:
                        if "detail" in results["error"]:
                            err = results["error"]["detail"]
                raise MeasurementProcessingError(str(err))
        except Exception as e:
            raise MeasurementProcessingError(
                "Error while retrieving results: {}".format(str(e))
            )

    def run_once(self, start=None, stop=None, latest_results=None):
        self.download_and_process(start, stop, latest_results)

    def run_continously(self, start=None):
        try:
            self.download_and_process(start=start)

            logger.info(
                "Waiting {} seconds (measurement's interval) before "
                "downloading new results...".format(self.msm_interval)
            )

            time.sleep(self.msm_interval)
        except KeyboardInterrupt:
            pass

    def run(self, start=None, stop=None, latest_results=None):
        self.acquire_lock()

        logger.info("Starting {}".format(str(self)))

        try:
            if self.stream:
                self.run_stream()

            elif not self.msm_is_oneoff and self.msm_is_running and \
                    not latest_results and not stop:

                self.run_continously(start=start)

            else:
                self.download_and_process(start=start, stop=stop,
                                          latest_results=latest_results)
        finally:
            self.release_lock()
