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

import re

from .Errors import ConfigError
from .ExpResCriteriaBase import ExpResCriterion
from .Logging import logger
from .ParsedResults import ParsedResult_DstAS, ParsedResult_UpstreamAS, \
                           ParsedResult_ASPath


class ExpResCriterion_DstAS(ExpResCriterion):
    """Criterion: dst_as

    Verify the traceroute destination's AS number.

    Available for: traceroute

    `dst_as`: list of Autonomous System numbers.

    It builds the path of ASs traversed by the traceroute.
    Match when the last AS in the path is one of the expected ones.

    Examples:

    dst_as:
    - 64496

    dst_as:
    - 64496
    - 65551
    """

    CRITERION_NAME = "dst_as"
    AVAILABLE_FOR_MSM_TYPE = ["traceroute"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.dst_as = self._enforce_list("dst_as", int)

    def __str__(self):
        return "Destination AS: {}".format(self._str_list())

    def display_string(self):
        more_than_one = len(self.dst_as) > 1
        return(
            "    - target must be in {}the following ASN{}: {}".format(
                "one of " if more_than_one else "",
                "s" if more_than_one else "",
                self._str_list()
            )
        )

    def prepare(self, result):
        res = ParsedResult_DstAS(self.expres.monitor, result)
        self.res_dst_as = res.dst_as

    def result_matches(self, result):
        logger.debug(
            "  verifying if destination AS {} in {}...".format(
                self.res_dst_as, self._str_list()
            )
        )

        if self.res_dst_as not in self.dst_as:
            return False

        return True


class ExpResCriterion_ASPath(ExpResCriterion):
    """Criterion: as_path

    Verify the path of ASs traversed by a traceroute.

    Available for: traceroute

    `as_path`: list of Autonomous System path.

    An AS path is made of AS numbers separated by white spaces. It can
    contain two special tokens:

    - "S", that is expanded with the probe's source AS number;

    - "IX", that represents an Internet Exchange Point peering network for
      those IXPs which don't announce their peering prefixes via BGP.

    The "IX" token is meagniful only if the `ip_cache.use_ixps_info`
    global configuration parameter is True.

    It builds the path of ASs traversed by the traceroute.
    Match when the AS path or a contiguous part of it is one of
    the expected ones.

    Examples:

    as_path: 64496 64497

    as_path:
    - 64496 64497
    - 64498 64499 64500

    as_path:
    - S 64496 64497

    as_path:
    - S IX 64500
    """

    CRITERION_NAME = "as_path"
    AVAILABLE_FOR_MSM_TYPE = ["traceroute"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.as_path = self._enforce_list("as_path", str)

        # AS path space-separated list of AS numbers

        for path in self.as_path:
            try:
                asns_list = path.split(" ")

                for asn in asns_list:
                    if not asn.isdigit() and asn not in ["S", "IX"]:
                        raise ConfigError(
                            "Invalid ASN: {}".format(asn)
                        )
            except Exception as e:
                raise ConfigError(
                    "Invalid syntax for as_path {} - {}. It must be a "
                    "space-separated list of AS numbers. The 'S' string "
                    "can be used to match the source probe's "
                    "ASN. The 'IX' string can be used to match crossing "
                    "of any peering LAN for those IXs which don't "
                    "announce their peering LAN prefixes".format(path, str(e))
                )

    def __str__(self):
        return "AS path: {}".format(self._str_list())

    def display_string(self):
        more_than_one = len(self.as_path) > 1
        return(
            "    - target must be reached via {}the following "
            "AS path{}: {}".format(
                "one of " if more_than_one else "",
                "s" if more_than_one else "",
                self._str_list()
            )
        )

    def prepare(self, result):
        res = ParsedResult_ASPath(self.expres.monitor, result)
        self.res_as_path = res.as_path
        self.res_as_path_ixps = res.as_path_ixps

    def result_matches(self, result):
        matching_as_path_found = False

        probe = self.monitor.get_probe(result)

        # if the expected path contains the 'IX' macro, it is
        # tested against the as_path_ixps list, otherwise against
        # the as_path list

        for exp_as_path in self.as_path:
            if "IX" in exp_as_path:
                path = " ".join(self.res_as_path_ixps)
            else:
                path = " ".join(self.res_as_path)

            logger.debug(
                "  verifying if AS path {} matches {}...".format(
                    path, exp_as_path
                )
            )

            if re.search(
                r" {} ".format(
                    exp_as_path.replace("S", str(probe.asn))
                ),
                " {} ".format(path.replace("S", str(probe.asn)))
            ):
                logger.debug(
                    "    path {} matches {}".format(
                        path, exp_as_path
                    )
                )
                matching_as_path_found = True
                break

        return matching_as_path_found


class ExpResCriterion_UpstreamAS(ExpResCriterion):
    """Criterion: upstream_as

    Verify the traceroute destination upstream's AS number.

    Available for: traceroute

    `upstream_as`: list of Autonomous System numbers.

    It builds the path of ASs traversed by the traceroute.
    Match when the penultimate AS in the path is one of the expected ones.

    Examples:

    upstream_as:
    - 64496

    upstream_as:
    - 64496
    - 64497
    """

    CRITERION_NAME = "upstream_as"
    AVAILABLE_FOR_MSM_TYPE = ["traceroute"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.upstream_as = self._enforce_list("upstream_as", int)

    def __str__(self):
        return "Target upstream AS: {}".format(self._str_list())

    def display_string(self):
        more_than_one = len(self.upstream_as) > 1
        return(
            "    - target must be reached via {}the following "
            "upstream ASN{}: {}".format(
                "one of " if more_than_one else "",
                "s" if more_than_one else "",
                self._str_list()
            )
        )

    def prepare(self, result):
        res = ParsedResult_UpstreamAS(self.expres.monitor, result)
        self.res_upstream_as = res.upstream_as

    def result_matches(self, result):
        upstream_as = self.res_upstream_as

        logger.debug(
            "  verifying if upstream AS {} in {}...".format(
                upstream_as, self._str_list()
            )
        )

        if upstream_as not in self.upstream_as:
            return False

        return True
