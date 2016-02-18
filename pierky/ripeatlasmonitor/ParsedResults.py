from ripe.atlas.sagan import PingResult, TracerouteResult, DnsResult, SslResult

from .Errors import ProgramError, ResultProcessingError
from .Logging import logger


class ParsedResult(object):

    def __init__(self, monitor, result):
        self.monitor = monitor
        self.cache = monitor.parsed_res
        self.result = result

    def __str__(self):
        return "parsed result for {} at {}".format(
            self.monitor.get_probe(self.result), self.result.created
        )

    def _get_cached_data(self):
        prb_id = str(self.result.probe_id)
        res_time = str(self.result.created)
        return self.cache[prb_id][res_time]

    def _create_cached_data(self):
        prb_id = str(self.result.probe_id)
        res_time = str(self.result.created)
        if prb_id not in self.cache:
            self.cache[prb_id] = {}
        if res_time not in self.cache[prb_id]:
            self.cache[prb_id][res_time] = {}
        return self.cache[prb_id][res_time]

    def get_attr_from_cache(self, attr):
        try:
            return self._get_cached_data()[attr]
        except KeyError:
            self.prepare()

            try:
                return self._get_cached_data()[attr]
            except KeyError:
                raise ProgramError(
                    "Can't find '{}' attribute on {}".format(attr, self)
                )

    def set_attr_to_cache(self, attr, val):
        self._create_cached_data()[attr] = val

    def prepare(self):
        raise NotImplemented


class ParsedResult_RTT(ParsedResult):

    PROPERTIES = ["rtt"]

    @property
    def rtt(self):
        return self.get_attr_from_cache("rtt")

    def prepare(self):
        if isinstance(self.result, TracerouteResult):
            res_rtt = self.result.last_median_rtt
        elif isinstance(self.result, PingResult):
            res_rtt = self.result.rtt_median
        else:
            raise NotImplementedError()

        self.set_attr_to_cache("rtt", res_rtt)


class ParsedResult_DstResponded(ParsedResult):

    PROPERTIES = ["responded"]

    @property
    def responded(self):
        return self.get_attr_from_cache("responded")

    def prepare(self):
        if isinstance(self.result, TracerouteResult):
            res_responded = self.result.destination_ip_responded
        elif isinstance(self.result, PingResult):
            res_responded = self.result.packets_received > 0
        else:
            raise NotImplementedError()

        self.set_attr_to_cache("responded", res_responded)


class ParsedResult_DstIP(ParsedResult):

    PROPERTIES = ["dst_ip"]

    @property
    def dst_ip(self):
        return self.get_attr_from_cache("dst_ip")

    def prepare(self):
        if isinstance(self.result, (TracerouteResult, PingResult, SslResult)):
            res_dst_ip = self.result.destination_address
        else:
            raise NotImplementedError()

        self.set_attr_to_cache("dst_ip", res_dst_ip)


class ParsedResult_CertFps(ParsedResult):

    PROPERTIES = ["cer_fps"]

    @property
    def cer_fps(self):
        return self.get_attr_from_cache("cer_fps")

    def prepare(self):
        if not isinstance(self.result, SslResult):
            raise NotImplementedError()

        res_cer_fps = \
            [cer.checksum_sha256.upper() for cer in self.result.certificates]
        res_cer_fps = sorted(res_cer_fps)

        self.set_attr_to_cache("cer_fps", res_cer_fps)


class ParsedResult_TracerouteBased(ParsedResult):

    PROPERTIES = ["as_path", "as_path_ixps"]

    @property
    def as_path(self):
        return self.get_attr_from_cache("as_path")

    @property
    def as_path_ixps(self):
        return self.get_attr_from_cache("as_path_ixps")

    def prepare(self):
        if not isinstance(self.result, TracerouteResult):
            raise NotImplementedError()

        probe = self.monitor.get_probe(self.result)

        # res_as_path contains the AS path with disregard of IXPs
        # example: IX1 is an IXP which doesn't announce its peering LAN pfx
        #   123 IX1 456 becomes res_as_path = ["123", "456"]
        res_as_path = [str(probe.asn)]

        # res_as_path_ixps contains the AS path with 'IX' in place of IXP
        #   peering LAN for those IXPs that don't announce their peering
        #   LAN pfx
        # example: IX1 is an IXP which doesn't announce its peering LAN pfx
        #   123 IX1 456 ==> res_as_path_ixps = ["123", "IX", "456"]
        # example: IX2 is an IXP which do announce its peering LAN pfx
        #   123 IX2 (AS789) 456 ==> res_as_path_ixps = ["123", "789", "456"]
        res_as_path_ixps = [str(probe.asn)]

        try:
            for hop in self.result.hops:
                for pkt in hop.packets:
                    if pkt.origin:
                        ip = pkt.origin

                        ip_info = self.monitor.ip_cache.get_ip_info(ip)

                        asn = ""

                        if ip_info["ASN"].isdigit():
                            asn = ip_info["ASN"]

                            if asn != res_as_path[-1]:
                                res_as_path.append(asn)

                            if asn != res_as_path_ixps[-1]:
                                res_as_path_ixps.append(asn)

                            break

                        elif ip_info["IsIXP"]:
                            asn = "IX"

                            if asn != res_as_path_ixps[-1]:
                                res_as_path_ixps.append(asn)

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

        self.set_attr_to_cache("as_path", res_as_path)
        self.set_attr_to_cache("as_path_ixps", res_as_path_ixps)


class ParsedResult_DNSBased(ParsedResult):

    def __init__(self, monitor, result, response):
        ParsedResult.__init__(self, monitor, result)
        self.response = response

        if not self.response.abuf:
            raise NotImplementedError()

    def __str__(self):
        return "parsed result for response ID {} of {} at {}".format(
            self.response.id,
            self.monitor.get_probe(self.result), self.result.created
        )

    def _get_cached_data(self):
        prb_id = str(self.result.probe_id)
        res_time = str(self.result.created)
        response_id = str(self.response.response_id)
        return self.cache[prb_id][res_time][response_id]

    def _create_cached_data(self):
        prb_id = str(self.result.probe_id)
        res_time = str(self.result.created)
        response_id = str(self.response.response_id)
        if prb_id not in self.cache:
            self.cache[prb_id] = {}
        if res_time not in self.cache[prb_id]:
            self.cache[prb_id][res_time] = {}
        if response_id not in self.cache[prb_id][res_time]:
            self.cache[prb_id][res_time][response_id] = {}
        return self.cache[prb_id][res_time][response_id]


class ParsedResult_DNSFlags(ParsedResult_DNSBased):

    PROPERTIES = ["flags"]

    DNS_HEADER_FLAGS = ("aa", "ad", "cd", "qr", "ra", "rd")

    @property
    def flags(self):
        return self.get_attr_from_cache("flags")

    def prepare(self):
        if not isinstance(self.result, DnsResult):
            raise NotImplementedError()

        response_flags = set()
        for flag in self.DNS_HEADER_FLAGS:
            if getattr(self.response.abuf.header, flag):
                response_flags.add(flag)

        self.set_attr_to_cache("flags", sorted(response_flags))


class ParsedResult_EDNS(ParsedResult_DNSBased):

    PROPERTIES = ["edns", "edns_size", "edns_do"]

    @property
    def edns(self):
        return self.get_attr_from_cache("edns")

    @property
    def edns_size(self):
        return self.get_attr_from_cache("edns_size")

    @property
    def edns_do(self):
        return self.get_attr_from_cache("edns_do")

    def prepare(self):
        if not isinstance(self.result, DnsResult):
            raise NotImplementedError()

        self.set_attr_to_cache("edns", self.response.abuf.edns0 is not None)

        if not self.response.abuf.edns0:
            self.set_attr_to_cache("edns_size", None)
            self.set_attr_to_cache("edns_do", None)
            return

        self.set_attr_to_cache("edns_size", self.response.abuf.edns0.udp_size)
        self.set_attr_to_cache("edns_do", self.response.abuf.edns0.do)
