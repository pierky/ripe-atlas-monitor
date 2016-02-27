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

import datetime
import json
import os
from six.moves.queue import Queue, Empty
import time
from threading import Thread

import pytz
import yaml

from .Action import ACTION_CLASSES
from .Config import Config
from .Errors import ConfigError, MissingFileError, \
                    MeasurementProcessingError, \
                    LockError, ProgramError
from .ExpectedResult import ExpectedResult
from .Helpers import BasicConfigElement, LockFile, ProbesFilter
from .Logging import logger
from .MsmProcessingUnit import MsmProcessingUnit
from ripe.atlas.cousteau import AtlasStream
from ripe.atlas.sagan import Result
from .Rule import Rule


class MonitorResultsThread(Thread):
    def __init__(self, monitor, probes_filter):
        Thread.__init__(self)
        self.monitor = monitor
        self.probes_filter = probes_filter

    def run(self):
        while not self.monitor.exit_thread:
            try:
                result = self.monitor.results_queue.get(True, 1)
                self.monitor.process_results([result], self.probes_filter)
            except Empty:
                pass


class Monitor(BasicConfigElement, MsmProcessingUnit):
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

        BasicConfigElement.__init__(self, cfg)

        self.normalize_fields()

        self.descr = self._enforce_param("descr", str)

        self._enforce_param("matching_rules", list)

        self._enforce_param("expected_results", dict) or {}

        self._enforce_param("actions", dict)

        MsmProcessingUnit.__init__(
            self,
            ip_cache=ip_cache,
            msm_id=msm_id or self._enforce_param("measurement-id", int),
            key=key or self._enforce_param("key", str),
            key_file=self._enforce_param("key_file", str)
        )

        self.stream = self._enforce_param("stream", bool) or False

        self.stream_timeout = self._enforce_param("stream_timeout", int)

        if self.stream:
            self.ensure_streaming_enabled(ConfigError)

        # Expected results normalization

        self.expected_results = {}

        if self.cfg["expected_results"]:
            for expres_name in self.cfg["expected_results"]:
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
            for action_name in self.cfg["actions"]:
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
                        if action_name not in self.actions:
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

    def process_results(self, results, probes_filter):
        logger.info("Processing results...")

        # Be sure to have info for every probe in the resultset
        self.update_probes(results)

        if len(results) == 0:
            logger.info("No results found.")
            return

        # Processing results...

        for json_result in results:
            result = Result.get(json_result, on_error=Result.ACTION_IGNORE,
                                on_malformation=Result.ACTION_IGNORE)

            probe = self.get_probe(result)
            if probe not in probes_filter:
                logger.debug(
                    "  skipping {} because of probes filter".format(probe)
                )
                continue

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

    def ensure_streaming_enabled(self, exception_class):
        err = "Can't use results streaming for this measurement: {}"

        if self.msm_is_oneoff:
            raise exception_class(
                err.format("it's a one-off measurement.")
            )

        if not self.msm_is_running:
            raise exception_class(
                err.format("it is not running anymore.")
            )

        if not self.msm_is_public:
            raise exception_class(
                err.format("it is not public.")
            )

    def run_stream(self, probes_filter):
        logger.info(" - using real-time results streaming")

        self.ensure_streaming_enabled(MeasurementProcessingError)

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
        thread = MonitorResultsThread(self, probes_filter)

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

    def get_latest_result_ts(self):
        if "latest_result_ts" in self.status:
            return self.status["latest_result_ts"]
        return None

    def run_once(self, probes_filter, start=None, stop=None,
                 latest_results=None):
        fetch_only_probe_ids = probes_filter.probe_ids

        results = self.download(start=start, stop=stop,
                                latest_results=latest_results,
                                probe_ids=fetch_only_probe_ids)

        self.process_results(results, probes_filter)

    def run_continously(self, start, probes_filter):
        try:
            while True:
                self.run_once(probes_filter, start=start)

                logger.info(
                    "Waiting {} seconds (measurement's interval) before "
                    "downloading new results...".format(self.msm_interval)
                )

                time.sleep(self.msm_interval)
        except KeyboardInterrupt:
            pass

    def run(self, start=None, stop=None, latest_results=None, dont_wait=False,
            probes_filter=None):
        self.acquire_lock()

        if not probes_filter:
            probes_filter = ProbesFilter()

        logger.info("Starting {}".format(str(self)))

        try:
            if self.stream:
                self.run_stream(probes_filter)

            elif not self.msm_is_oneoff and self.msm_is_running and \
                    not latest_results and not stop and not dont_wait:

                self.run_continously(start, probes_filter)

            else:
                self.run_once(probes_filter, start=start, stop=stop,
                              latest_results=latest_results)
        finally:
            self.release_lock()
