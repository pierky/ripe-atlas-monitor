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
import os

import pytz

from .Config import Config
from .Errors import ConfigError, MissingFileError, \
                    MeasurementProcessingError, \
                    ResultProcessingError
from .Helpers import Probe
from .Logging import logger
from ripe.atlas.cousteau import AtlasResultsRequest, AtlasLatestRequest, \
                                ProbeRequest, Measurement
from ripe.atlas.cousteau.exceptions import CousteauGenericError, \
                                           APIResponseError
from ripe.atlas.sagan import Result


class MsmProcessingUnit(object):
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

    def __init__(self, ip_cache=None, msm_id=None, key=None, key_file=None):
        self.ip_cache = ip_cache

        self.msm_id = msm_id

        if self.msm_id is None:
            raise ConfigError(
                "Missing measurement ID: it must be specified in the "
                "monitor configuration file or provided using the "
                "command line argument --measurement-id."
            )

        self.key = key
        self.key_file = key_file

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

        # Measurement validation

        msm = self._load_msm(id=self.msm_id, key=self.key)

        self.msm_is_public = msm.is_public
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

    def get_latest_result_ts(self):
        # Must be implemented in child classes
        raise NotImplementedError()

    def download(self, start=None, stop=None, latest_results=None,
                 probe_ids=None):
        atlas_params = {
            "msm_id": self.msm_id,
            "key": self.key
        }

        if probe_ids:
            assert isinstance(probe_ids, list)
            assert all(isinstance(_, int) for _ in probe_ids)
            atlas_params["probe_ids"] = probe_ids

            logger.info(
                "Downloading results for probe ID{s}{IDs}{more}...".format(
                    s="s " if len(probe_ids) > 1 else " ",
                    IDs=", ".join(map(str, probe_ids[0:3])),
                    more=" and {} more".format(len(probe_ids) - 3)
                         if len(probe_ids) > 3 else ""
                )
            )
        else:
            logger.info("Downloading results...")

        if not latest_results:
            atlas_class = AtlasResultsRequest

            msm_results_days_limit = Config.get("misc.msm_results_days_limit")
            latest_result_ts = self.get_latest_result_ts()

            if start:
                tpl = "{start}"

            elif latest_result_ts:
                start = datetime.datetime.fromtimestamp(
                    latest_result_ts + 1, tz=pytz.UTC
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
        except Exception as e:
            raise MeasurementProcessingError(
                "Error while retrieving results: {}".format(str(e))
            )

        if is_success:
            return results
        else:
            err = str(results)
            if isinstance(results, dict):
                if "detail" in results:
                    err = results["detail"]
                elif "error" in results:
                    if "detail" in results["error"]:
                        err = results["error"]["detail"]
            raise MeasurementProcessingError(str(err))
