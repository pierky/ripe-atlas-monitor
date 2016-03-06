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

import IPy

from .Errors import ConfigError, ResultProcessingError
from .ExpResCriteriaBase import ExpResCriterion
from .Logging import logger
from .ParsedResults import ParsedResult_RTT, ParsedResult_DstResponded, \
                           ParsedResult_DstIP


class ExpResCriterion_RTT(ExpResCriterion):
    """Criterion: rtt

    Test the median round trip time toward destination.

    Available for: ping, traceroute.

    `rtt`: maximum RTT (in ms).

    `rtt_tolerance` (optional): tolerance (in %) on `rtt`.

    If `rtt_tolerance` is not given, match when measured RTT is less
    than `rtt`, otherwise match when measured RTT is within `rtt`
    +/- `rtt_tolerance` %.

    Examples:

    expected_results:
      LowRTT:
        rtt: 50
      Near150:
        rtt: 150
        rtt_tolerance: 30
    """

    CRITERION_NAME = "rtt"
    AVAILABLE_FOR_MSM_TYPE = ["traceroute", "ping"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = ["rtt_tolerance"]

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.rtt = self._enforce_param("rtt", int)
        self.rtt_tolerance = self._enforce_param("rtt_tolerance", int) or 0

    def __str__(self):
        if self.rtt:
            if self.rtt_tolerance:
                return "RTT must be within {}ms +/- {}%".format(
                    self.rtt, self.rtt_tolerance
                )
            else:
                return "RTT must be less than {}ms".format(
                        self.rtt
                )

    def prepare(self, result):
        res = ParsedResult_RTT(self.expres.monitor, result)
        self.res_rtt = res.rtt

    def result_matches(self, result):
        result_rtt = self.res_rtt

        if result_rtt:
            if not self.rtt_tolerance:
                logger.debug(
                    "  verifying if RTT {} < {}...".format(
                        result_rtt, self.rtt
                    )
                )

                if result_rtt > self.rtt:
                    return False
            else:
                logger.debug(
                    "  verifying if RTT {} within {} +/- {}%...".format(
                        result_rtt, self.rtt,
                        self.rtt_tolerance
                    )
                )

                delta = self.rtt * self.rtt_tolerance / 100
                if abs(self.rtt - result_rtt) > delta:
                    return False
        else:
            raise ResultProcessingError(
                "Can't verify RTT: RTT is unknown"
            )

        return True


class ExpResCriterion_DstResponded(ExpResCriterion):
    """Criterion: dst_responded

    Verify if destination responded.

    Available for: traceroute, ping, sslcert.

    `dst_responded`: boolean indicating if the destination is expected to be
    responding or not.

    For ping, a destination is responding if a probe received at least one
    reply packet.
    For sslcert, a destination is responding if at least one certificate is
    received by the probe.

    If `dst_responded` is True, match when a destination is responding.
    If `dst_responded` is False, match when a destination is not responding.

    Example:

    expected_results:
      DestinationReachable:
        dst_responded: True
    """

    CRITERION_NAME = "dst_responded"
    AVAILABLE_FOR_MSM_TYPE = ["traceroute", "ping", "sslcert"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.dst_responded = self._enforce_param("dst_responded", bool)

    def __str__(self):
        if self.dst_responded:
            return "Destination must respond"
        else:
            return "Destination must not respond"

    def prepare(self, result):
        res = ParsedResult_DstResponded(self.expres.monitor, result)
        self.res_responded = res.responded

    def result_matches(self, result):
        result_responded = self.res_responded

        logger.debug(
            "  testing if target responded ({}) is {}...".format(
                result_responded, self.dst_responded
            )
        )

        if result_responded and not self.dst_responded:
            logger.debug("  target responded while it should not")
            return False
        if not result_responded and self.dst_responded:
            logger.debug("  target did not respond")
            return False

        return True


class ExpResCriterion_DstIP(ExpResCriterion):
    """Criterion: dst_ip

    Verify that the destination IP used by the probe for the measurement is
    the expected one.

    Available for: traceroute, ping, sslcert.

    `dst_ip`: list of expected IP addresses (or prefixes).

    Match when the probe destination IP is one of the expected ones (or falls
    within one of the expected prefixes).

    Examples:

    dst_ip: 192.168.0.1

    dst_ip:
    - 192.168.0.1
    - 2001:DB8::1

    dst_ip:
    - 192.168.0.1
    - 10.0.0.0/8
    - 2001:DB8::/32
    """

    CRITERION_NAME = "dst_ip"
    AVAILABLE_FOR_MSM_TYPE = ["traceroute", "ping", "sslcert"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.dst_ip = []
        dst_ip = self._enforce_list("dst_ip", str)

        for ip in dst_ip:
            try:
                self.dst_ip.append(IPy.IP(ip))
            except:
                raise ConfigError("Invalid IP address/net: {}".format(ip))

    def __str__(self):
        all_subnets = True
        for ip in self.dst_ip:
            all_subnets = all_subnets and ip.prefixlen() not in [32, 128]

        more_than_one = len(self.dst_ip) > 1

        if all_subnets:
            tpl = "Destination IP must fall into {}"
        else:
            if more_than_one:
                tpl = "Destination IP must be in {}"
            else:
                tpl = "Destination IP must be {}"

        return tpl.format(self._str_list())

    def prepare(self, result):
        res = ParsedResult_DstIP(self.expres.monitor, result)
        self.res_dst_ip = res.dst_ip

    def result_matches(self, result):
        result_dst_ip = self.res_dst_ip

        try:
            result_dst_ip = IPy.IP(result_dst_ip)
        except:
            raise ResultProcessingError(
                "Invalid destination IP address: {}".format(result_dst_ip)
            )

        match = False

        for dst_ip in self.dst_ip:
            if dst_ip.prefixlen() not in [32, 128]:
                logger.debug(
                    "  verifying if destination IP {} falls into "
                    "the expected subnet ({})...".format(
                        result_dst_ip, dst_ip
                    )
                )

                match = result_dst_ip in dst_ip
            else:
                logger.debug(
                    "  verifying if destination IP {} matches "
                    "the expected one ({})".format(
                        result_dst_ip, self.dst_ip
                    )
                )

                match = result_dst_ip == dst_ip

            if match:
                break

        return match
