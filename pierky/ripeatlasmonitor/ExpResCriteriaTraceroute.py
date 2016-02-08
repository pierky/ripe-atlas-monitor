import re

from Errors import ConfigError, ResultProcessingError
from ExpResCriteriaBase import ExpResCriterion
from Logging import logger


class ExpResCriterion_TracerouteBased(ExpResCriterion):

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        self.res_as_path = None
        self.res_as_path_ixps = None

    def prepare(self, result):
        if self.monitor.msm_type != "traceroute":
            raise NotImplementedError()

        self.res_as_path = self.get_parsed_res(result, result.probe_id,
                                               "res_as_path")
        self.res_as_path_ixps = self.get_parsed_res(result, result.probe_id,
                                                    "res_as_path_ixps")

        if self.res_as_path:
            return

        self.parse_data(result)

    def parse_data(self, result):
        probe = self.monitor.get_probe(result)

        # res_as_path contains the AS path with disregard of IXPs
        # example: IX1 is an IXP which doesn't announce its peering LAN pfx
        #   123 IX1 456 becomes res_as_path = ["123", "456"]
        self.res_as_path = [str(probe.asn)]

        # res_as_path_ixps contains the AS path with 'IX' in place of IXP
        #   peering LAN for those IXPs that don't announce their peering
        #   LAN pfx
        # example: IX1 is an IXP which doesn't announce its peering LAN pfx
        #   123 IX1 456 ==> res_as_path_ixps = ["123", "IX", "456"]
        # example: IX2 is an IXP which do announce its peering LAN pfx
        #   123 IX2 (AS789) 456 ==> res_as_path_ixps = ["123", "789", "456"]
        self.res_as_path_ixps = [str(probe.asn)]

        try:
            for hop in result.hops:
                for pkt in hop.packets:
                    if pkt.origin:
                        ip = pkt.origin

                        ip_info = self.monitor.ip_cache.get_ip_info(ip)

                        asn = ""

                        if ip_info["ASN"].isdigit():
                            asn = ip_info["ASN"]

                            if asn != self.res_as_path[-1]:
                                self.res_as_path.append(asn)

                            if asn != self.res_as_path_ixps[-1]:
                                self.res_as_path_ixps.append(asn)

                            break

                        elif ip_info["IsIXP"]:
                            asn = "IX"

                            if asn != self.res_as_path_ixps[-1]:
                                self.res_as_path_ixps.append(asn)

                            break
        except Exception as e:
            logger.error(
                "Can't get IP addresses / ASNs details: "
                "{}".format(str(e)),
                exc_info=True
            )
            raise ResultProcessingError(
                "Can't get IP addresses / ASNs details: "
                "{}".format(str(e))
            )

        self.set_parsed_res(result, probe.id, "res_as_path",
                            self.res_as_path)
        self.set_parsed_res(result, probe.id, "res_as_path_ixps",
                            self.res_as_path_ixps)


class ExpResCriterion_DstAS(ExpResCriterion_TracerouteBased):
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
        ExpResCriterion_TracerouteBased.__init__(self, cfg, expres)

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

    def result_matches(self, result):
        logger.debug(
            "  verifying if destination AS {} in {}...".format(
                self.res_as_path[-1], self._str_list()
            )
        )

        if int(self.res_as_path[-1]) not in self.dst_as:
            return False

        return True


class ExpResCriterion_ASPath(ExpResCriterion_TracerouteBased):
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
        ExpResCriterion_TracerouteBased.__init__(self, cfg, expres)

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
                " {} ".format(path)
            ):
                logger.debug(
                    "    path {} matches {}".format(
                        path, exp_as_path
                    )
                )
                matching_as_path_found = True
                break

        return matching_as_path_found


class ExpResCriterion_UpstreamAS(ExpResCriterion_TracerouteBased):
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
        ExpResCriterion_TracerouteBased.__init__(self, cfg, expres)

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

    def result_matches(self, result):
        if len(self.res_as_path) > 1:
            upstream_as = int(self.res_as_path[-2])

            logger.debug(
                "  verifying if upstream AS {} in {}...".format(
                    upstream_as, self._str_list()
                )
            )

            if upstream_as not in self.upstream_as:
                return False
        else:
            raise ResultProcessingError(
                "Can't verify target upstream AS: "
                "only one ASN found ({}).".format(
                    self.res_as_path[0]
                )
            )

        return True
