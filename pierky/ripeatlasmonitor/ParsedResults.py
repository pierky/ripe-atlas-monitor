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

from ripe.atlas.sagan import PingResult, TracerouteResult, DnsResult, SslResult

from .Errors import ProgramError, ResultProcessingError
from .Logging import logger


class ParsedResult(object):
    """ParsedResult

    Each ParsedResult object exposes properties that can be used to analyze
    measurements and to match expected results.

    Each property must be listed in the PROPERTIES attribute and must have a
    corresponding @property method, that must be used to read its value.

    The prepare() method must implement everything needed to get the
    values of each property; these values must be stored using the
    self.set_attr_to_cache() method.

    The @property methods must read the values they need to return using the
    self.get_attr_from_cache() method.

    Keep this docstring in sync with docs/CONTRIBUTING.rst file.
    """

    PROPERTIES = []

    def __init__(self, msm_proc_unit, result):
        self.msm_proc_unit = msm_proc_unit
        self.cache = msm_proc_unit.parsed_res
        self.result = result

    def __str__(self):
        return "parsed result for {} at {}".format(
            self.msm_proc_unit.get_probe(self.result), self.result.created
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
        elif isinstance(self.result, SslResult):
            res_responded = len(self.result.certificates) > 0
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

    @property
    def as_path(self):
        return self.get_attr_from_cache("as_path")

    @property
    def as_path_ixps(self):
        return self.get_attr_from_cache("as_path_ixps")

    def prepare(self):
        if not isinstance(self.result, TracerouteResult):
            raise NotImplementedError()

        probe = self.msm_proc_unit.get_probe(self.result)

        # res_as_path contains the AS path with disregard of IXPs
        # example: IX1 is an IXP which doesn't announce its peering LAN pfx
        #   123 IX1 456 becomes res_as_path = ["123", "456"]
        res_as_path = []

        # res_as_path_ixps contains the AS path with 'IX' in place of IXP
        #   peering LAN for those IXPs that don't announce their peering
        #   LAN pfx
        # example: IX1 is an IXP which doesn't announce its peering LAN pfx
        #   123 IX1 456 ==> res_as_path_ixps = ["123", "IX", "456"]
        # example: IX2 is an IXP which do announce its peering LAN pfx
        #   123 IX2 (AS789) 456 ==> res_as_path_ixps = ["123", "789", "456"]
        res_as_path_ixps = []

        if probe.asn is not None:
            res_as_path.append("S")
            res_as_path_ixps.append("S")

        for hop in self.result.hops:
            for pkt in hop.packets:
                if not pkt.origin:
                    continue

                ip = pkt.origin

                try:
                    ip_info = self.msm_proc_unit.ip_cache.get_ip_info(ip)
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

                asn = ""

                if ip_info["ASN"].isdigit():
                    asn = ip_info["ASN"]
                    if probe.asn is not None and asn == str(probe.asn):
                        asn = "S"

                    if not res_as_path or asn != res_as_path[-1]:
                        res_as_path.append(asn)
                    if not res_as_path_ixps or asn != res_as_path_ixps[-1]:
                        res_as_path_ixps.append(asn)

                    break
                elif ip_info["IsIXP"]:
                    asn = "IX"

                    if not res_as_path_ixps or asn != res_as_path_ixps[-1]:
                        res_as_path_ixps.append(asn)

                    break

        self.set_attr_to_cache("as_path", res_as_path)
        self.set_attr_to_cache("as_path_ixps", res_as_path_ixps)


class ParsedResult_DstAS(ParsedResult_TracerouteBased):

    PROPERTIES = ["dst_as"]

    @property
    def dst_as(self):
        return self.get_attr_from_cache("dst_as")

    def prepare(self):
        ParsedResult_TracerouteBased.prepare(self)

        if len(self.as_path) > 0:
            dst_as = self.as_path[-1].replace(
                "S", str(self.msm_proc_unit.get_probe(self.result).asn)
            )
            dst_as = int(dst_as)
            self.set_attr_to_cache("dst_as", dst_as)
        else:
            self.set_attr_to_cache("dst_as", None)


class ParsedResult_UpstreamAS(ParsedResult_TracerouteBased):

    PROPERTIES = ["upstream_as"]

    @property
    def upstream_as(self):
        return self.get_attr_from_cache("upstream_as")

    def prepare(self):
        ParsedResult_TracerouteBased.prepare(self)

        if len(self.as_path) > 1:
            upstream_as = self.as_path[-2].replace(
                "S", str(self.msm_proc_unit.get_probe(self.result).asn)
            )
            upstream_as = int(upstream_as)
            self.set_attr_to_cache("upstream_as", upstream_as)
        else:
            self.set_attr_to_cache("upstream_as", None)


class ParsedResult_ASPath(ParsedResult_TracerouteBased):

    PROPERTIES = ["as_path", "as_path_ixps"]


class ParsedResult_DNSBased(ParsedResult):

    def __init__(self, msm_proc_unit, result, response):
        ParsedResult.__init__(self, msm_proc_unit, result)
        self.response = response

        if not self.response.abuf:
            raise NotImplementedError()

    def __str__(self):
        return "parsed result for response ID {} of {} at {}".format(
            self.response.id,
            self.msm_proc_unit.get_probe(self.result), self.result.created
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


class ParsedResult_DNSHeader(ParsedResult_DNSBased):

    PROPERTIES = ["flags", "rcode"]

    DNS_HEADER_FLAGS = ("aa", "ad", "cd", "qr", "ra", "rd")

    # keep in sync with ExpResCriterion_DNSRCode docstring
    DNS_RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN",
                  "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
                  "NXRRSET", "NOTAUTH", "NOTZONE", "BADVERS"]

    @property
    def flags(self):
        return self.get_attr_from_cache("flags")

    @property
    def rcode(self):
        return self.get_attr_from_cache("rcode")

    def prepare(self):
        if not isinstance(self.result, DnsResult):
            raise NotImplementedError()

        self.set_attr_to_cache("flags", [])
        self.set_attr_to_cache("rcode", None)

        if not self.response.abuf:
            return

        response_flags = set()
        for flag in self.DNS_HEADER_FLAGS:
            if getattr(self.response.abuf.header, flag):
                response_flags.add(flag)

        self.set_attr_to_cache("flags", sorted(response_flags))
        self.set_attr_to_cache("rcode", self.response.abuf.header.return_code)


class ParsedResult_EDNS(ParsedResult_DNSBased):

    PROPERTIES = ["edns", "edns_size", "edns_do", "edns_nsid"]

    @property
    def edns(self):
        return self.get_attr_from_cache("edns")

    @property
    def edns_size(self):
        return self.get_attr_from_cache("edns_size")

    @property
    def edns_do(self):
        return self.get_attr_from_cache("edns_do")

    @property
    def edns_nsid(self):
        return self.get_attr_from_cache("edns_nsid")

    def prepare(self):
        if not isinstance(self.result, DnsResult):
            raise NotImplementedError()

        self.set_attr_to_cache("edns", self.response.abuf.edns0 is not None)

        self.set_attr_to_cache("edns_size", None)
        self.set_attr_to_cache("edns_do", None)
        self.set_attr_to_cache("edns_nsid", None)

        if not self.response.abuf.edns0:
            return

        self.set_attr_to_cache("edns_size", self.response.abuf.edns0.udp_size)
        self.set_attr_to_cache("edns_do", self.response.abuf.edns0.do)
        for option in self.response.abuf.edns0.options:
            if option.nsid:
                self.set_attr_to_cache("edns_nsid", option.nsid)


class ParsedResult_DNSAnswers(ParsedResult_DNSBased):
    # Used only for measurement analysis.
    # The ExpResCriterion_DNSAnswers class doesn't behave like
    # other ExpResCriterion-derived classes.

    PROPERTIES = ["dns_answers"]

    @property
    def dns_answers(self):
        return self.get_attr_from_cache("dns_answers")

    @staticmethod
    def get_record_info(record):
        # return touple (name, type, value)

        r = (record.name, record.type)
        if record.type in ["A", "AAAA"]:
            r += (record.address,)
        elif record.type in ["CNAME", "NS", "PTR"]:
            r += (record.target,)
        elif record.type == "MX":
            r += ("{} {}".format(record.preference, record.mail_exchanger),)
        elif record.type == "SOA":
            r += ("{} {} {} {} {} {} {}".format(
                record.mname, record.rname, record.serial, record.refresh,
                record.retry, record.expire, record.minimum),)
        elif record.type == "TXT":
            r += (record.data_string,)
        else:
            r += ("unhandled record type",)
        return r

    def prepare(self):
        if not isinstance(self.result, DnsResult):
            raise NotImplementedError()

        self.set_attr_to_cache("dns_answers", [])

        if not self.response.abuf:
            return

        records = [self.get_record_info(r)
                   for r in self.response.abuf.answers if r.name and r.type]

        if len(records) == 0:
            return

        ordered_records = sorted(records, key=lambda x: (x[0], x[1], x[2]))

        self.set_attr_to_cache("dns_answers", ordered_records)
