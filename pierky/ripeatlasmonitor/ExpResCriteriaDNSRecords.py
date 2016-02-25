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

from .Errors import ConfigError
from .Helpers import BasicConfigElement
from .Logging import logger


class ExpResCriterion_DNSRecord(BasicConfigElement):
    """DNS record

    Test properties which are common to all DNS record types.

    `type`: record's type. Must be one of the DNS record types implemented
    and described below.

    `name` (optional): list of expected names.

    `ttl_min` (optional): minimum TTL that is expected for the record.

    `ttl_max` (optional): maximum TTL that is expected for the record.

    `class` (optional): expected class for the record.

    Match when all the defined criteria are met:

    - record name must be within the list of given names (`name`);

    - record TTL must be >= `ttl_min` and <= `ttl_max`;

    - record class must be equal to `class`.

    On the basis of record's `type`, further parameters may be needed.

    Example:

    dns_answers:
        answers:
            - type: A
              name: www.ripe.net.
              address: 193.0.6.139
            - type: AAAA
              name:
              - www.ripe.net.
              - ripe.net.
              ttl_min: 604800
              address: 2001:67c:2e8:22::c100:0/64
    """

    RECORD_TYPE = ""
    MANDATORY_CFG_FIELDS = ["type"]
    OPTIONAL_CFG_FIELDS = ["name", "ttl_min", "ttl_max", "class"]

    @classmethod
    def get_cfg_fields(cls):
        m = set(ExpResCriterion_DNSRecord.MANDATORY_CFG_FIELDS)
        o = set(ExpResCriterion_DNSRecord.OPTIONAL_CFG_FIELDS)

        m.update(cls.MANDATORY_CFG_FIELDS)
        o.update(cls.OPTIONAL_CFG_FIELDS)

        return m, o

    def __init__(self, cfg):
        BasicConfigElement.__init__(self, cfg)
        self.normalize_fields()

        self.type = self._enforce_param("type", str)
        self.name = self._enforce_list("name", str)
        self.ttl_min = self._enforce_param("ttl_min", int)
        self.ttl_max = self._enforce_param("ttl_max", int)
        self.klass = self._enforce_param("class", str)

    def __str__(self):
        r = "{}: ".format(self.RECORD_TYPE)
        if self.name:
            if len(self.name) > 1:
                r += "name in {}, "
            else:
                r += "name {}, "
            r = r.format(", ".join(self.name))

        if self.ttl_min:
            r += "ttl < {}, ".format(self.ttl_min)

        if self.ttl_max:
            r += "ttl > {}, ".format(self.ttl_max)

        if self.klass:
            r += "class {}, ".format(self.klass)

        return r

    def record_base_matches(self, record):
        if self.RECORD_TYPE != record.type:
            logger.debug(
                "  record type {} is not {}".format(
                    record.type, self.RECORD_TYPE
                )
            )
            return False
        if self.name:
            if record.name not in self.name:
                logger.debug(
                    "  record name {} is not {}".format(
                        record.name, ", ".join(self.name)
                    )
                )
                return False
        if self.ttl_min:
            if record.ttl < self.ttl_min:
                logger.debug(
                    "  record TTL {} < {}".format(
                        record.ttl, self.ttl_min
                    )
                )
                return False
        if self.ttl_max:
            if record.ttl > self.ttl_max:
                logger.debug(
                    "  record TTL {} > {}".format(
                        record.ttl, self.ttl_max
                    )
                )
                return False
        if self.klass:
            if record.klass != self.klass:
                logger.debug(
                    "record class {} != {}".format(
                        record.klass, self.klass
                    )
                )
                return False
        return True

    def _record_matches(self, record):
        raise NotImplementedError()

    def record_matches(self, record):
        return self.record_base_matches(record) and \
            self._record_matches(record)


class ExpResCriterion_DNSRecord_A(ExpResCriterion_DNSRecord):
    """A record

    Verify if record's type is A and if received address match the
    expectations.

    `address`: list of IPv4 addresses (or IPv4 prefixes).

    Match when record's type is A and resolved address is one of the
    given addresses (or falls within one of the given prefixes).
    """

    RECORD_TYPE = "A"
    MANDATORY_CFG_FIELDS = ["address"]
    OPTIONAL_CFG_FIELDS = []

    IP_VER = 4

    def __init__(self, cfg):
        ExpResCriterion_DNSRecord.__init__(self, cfg)

        self.address = []
        addresses = self._enforce_list("address", str)
        for address in addresses:
            try:
                ip = IPy.IP(address)
            except:
                raise ConfigError(
                    "Invalid IP for {} record: {}".format(
                        self.RECORD_TYPE, address
                    )
                )
            if ip.version() != self.IP_VER:
                raise ConfigError(
                    "Invalid IP version ({}) for record type {}.".format(
                        ip.version(), self.RECORD_TYPE
                    )
                )
            self.address.append(ip)

    def _record_matches(self, record):
        try:
            ip = IPy.IP(record.address)
        except:
            logger.debug(
                "  invalid {} record from result: {}".format(
                    self.RECORD_TYPE, record.address
                )
            )
            return False

        logger.debug(
            "  verifying if {} matches {}...".format(
                str(ip), ", ".join(map(str, self.address))
            )
        )

        for address in self.address:
            if address.prefixlen() in [32, 128]:
                if address == ip:
                    return True
            else:
                if ip in address:
                    return True

        return False

    def __str__(self):
        return ExpResCriterion_DNSRecord.__str__(self) + \
            ", ".join(map(str, self.address))


class ExpResCriterion_DNSRecord_AAAA(ExpResCriterion_DNSRecord_A):
    """AAAA record

    Verify if record's type is AAAA and if received address match the
    expectations.

    `address`: list of IPv6 addresses (or IPv6 prefixes).

    Match when record's type is AAAA and resolved address is one of the
    given addresses (or falls within one of the given prefixes).
    """

    RECORD_TYPE = "AAAA"
    IP_VER = 6


class ExpResCriterion_DNSRecord_NS(ExpResCriterion_DNSRecord):
    """NS record

    Verify if record's type is NS and if target is one of the expected ones.

    `target`: list of expected targets.

    Match when record's type is NS and received target is one of those given
    in `target`.
    """

    RECORD_TYPE = "NS"
    MANDATORY_CFG_FIELDS = ["target"]
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg):
        ExpResCriterion_DNSRecord.__init__(self, cfg)

        self.target = self._enforce_list("target", str)

    def _record_matches(self, record):
        logger.debug(
            "  verifying if {} target {} in {}".format(
                self.RECORD_TYPE,
                record.target, ", ".join(self.target)
            )
        )
        return record.target in self.target

    def __str__(self):
        return ExpResCriterion_DNSRecord.__str__(self) + \
            ", ".join(map(str, self.target))


class ExpResCriterion_DNSRecord_CNAME(ExpResCriterion_DNSRecord_NS):
    """CNAME record

    Verify if record's type is CNAME and if target is one of the expected ones.

    `target`: list of expected targets.

    Match when record's type is CNAME and received target is one of those given
    in `target`.
    """

    RECORD_TYPE = "CNAME"


HANDLED_RECORD_TYPES = [
    ExpResCriterion_DNSRecord_A,
    ExpResCriterion_DNSRecord_AAAA,
    ExpResCriterion_DNSRecord_NS,
    ExpResCriterion_DNSRecord_CNAME
]
