from Errors import ConfigError
from ExpResCriteriaBase import ExpResCriterion
from ExpResCriteriaDNSRecords import HANDLED_RECORD_TYPES
from Logging import logger
from ParsedResults import ParsedResult_DNSFlags, ParsedResult_EDNS


class ExpResCriterion_DNSBased(ExpResCriterion):

    def response_matches(self, response):
        raise NotImplementedError()

    def prepare_response(self, result, response):
        raise NotImplementedError()

    def prepare(self, result):
        for response in result.responses:
            self.prepare_response(result, response)

    def result_matches(self, result):
        response_found = False
        for response in result.responses:
            if response.abuf:
                response_found = True

                if not self.response_matches(response):
                    return False

        if not response_found:
            logger.debug("  no response found")
        return response_found


class ExpResCriterion_DNSFlags(ExpResCriterion_DNSBased):
    """Criterion: dns_flags

    Verify if DNS responses received by a probe have the expected
    headers flags on.

    Available for: dns.

    `dns_flags`: list of expected DNS flag ("aa", "ad", "cd", "qr", "ra",
    "rd").

    Match when all the responses received by a probe have all the expected
    flags on.

    Example:

    expected_results:
      AA_and_AD:
        dns_flags:
        - aa
        - ad
    """

    CRITERION_NAME = "dns_flags"
    AVAILABLE_FOR_MSM_TYPE = ["dns"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion_DNSBased.__init__(self, cfg, expres)

        self.dns_flags = set()
        dns_flags = self._enforce_list("dns_flags", str)

        for flag in dns_flags:
            if flag.lower() not in ParsedResult_DNSFlags.DNS_HEADER_FLAGS:
                raise ConfigError("Invalid DNS flag: {}".format(flag))
            if flag.lower() not in self.dns_flags:
                self.dns_flags.add(flag.lower())

    def __str__(self):
        return "DNS response flags: {}".format(
            ", ".join(sorted(self.dns_flags))
        )

    def prepare_response(self, result, response):
        res = ParsedResult_DNSFlags(self.expres.monitor, result, response)
        self.response_flags = res.flags

    def response_matches(self, response):
        response_flags = self.response_flags

        logger.debug(
            "  verifying if expected flags ({}) are "
            "in the response's flags ({})...".format(
                ", ".join(self.dns_flags),
                ", ".join(response_flags)
            )
        )

        if not self.dns_flags.issubset(response_flags):
            return False

        return True


class ExpResCriterion_EDNS(ExpResCriterion_DNSBased):
    """Criterion: edns

    Verify EDNS extension of DNS responses received by probes.

    Available for: dns.

    `edns`: boolean indicating whether EDNS support is expected or not.

    `edns_size` (optional): minimum expected size.

    `edns_do` (optional): boolean indicating the expected presence of DO flag.

    The optional parameters are taken into account only when `edns` is True.

    If `edns` is True, match when all the responses contain EDNS extension,
    otherwise when all the responses do not contain it.
    If `edns_size` is given, the size reported must be >= than the expected
    one.
    If `edns_do` is given, all the responses must have (or have not) the DO
    flag on.

    Examples:

    edns: true

    edns: true
    edns_do: true
    """

    CRITERION_NAME = "edns"
    AVAILABLE_FOR_MSM_TYPE = ["dns"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = ["edns_size", "edns_do"]

    def __init__(self, cfg, expres):
        ExpResCriterion_DNSBased.__init__(self, cfg, expres)

        self.edns = self._enforce_param("edns", bool)
        self.edns_size = self._enforce_param("edns_size", int)
        self.edns_do = self._enforce_param("edns_do", bool)

    def __str__(self):
        if self.edns:
            r = "EDNS supported"
            if self.edns_size is not None:
                r += "; size >= {}".format(self.edns_size)
            if self.edns_do is not None:
                if self.edns_do:
                    r += "; DO flag on"
                else:
                    r += "; DO flag off"
        else:
            r = "EDNS not supported"
        return r

    def prepare_response(self, result, response):
        res = ParsedResult_EDNS(self.expres.monitor, result, response)
        self.response_edns = res.edns
        self.response_edns_size = res.edns_size
        self.response_edns_do = res.edns_do

    def response_matches(self, response):
        if self.response_edns and not self.edns:
            logger.debug(
                "  EDNS is supported while it shouldn't"
            )
            return False

        if not self.response_edns and self.edns:
            logger.debug(
                "  EDNS is not supported while it should be"
            )
            return False

        if self.edns and self.edns_size:
            if self.response_edns_size < self.edns_size:
                logger.debug(
                    "  EDNS udp size {} < {}".format(
                        self.response_edns_size, self.edns_size
                    )
                )
                return False

        if self.edns and self.edns_do is not None:
            if self.response_edns_do and not self.edns_do:
                logger.debug(
                    "  EDNS DO flag is on while it should be off"
                )
                return False

            if not self.response_edns_do and self.edns_do:
                logger.debug(
                    "  EDNS DO flag is off while is should be on"
                )
                return False

        return True


class ExpResCriterion_AnswersSection(object):
    """DNS answer section

    One of "answers", "authorities", "additionals".

    Each section must contain a list of DNS records.
    """

    def __init__(self, name, cfg):
        self.name = name
        self.records = []
        for record_cfg in cfg:
            self.add_record(record_cfg)

    def add_record(self, record_cfg):

        if "type" not in record_cfg:
            raise ConfigError("Missing mandatory attribute: type")

        record_class = None
        for record_class in HANDLED_RECORD_TYPES:
            if record_class.RECORD_TYPE.lower() == record_cfg["type"].lower():
                self.records.append(record_class(record_cfg))
                return

        raise ConfigError(
            "Unhandled record type: {}".format(
                record_cfg["type"]
            )
        )

    def __str__(self):
        return "Section {}: {}".format(
            self.name,
            ", ".join(map(str, self.records))
        )


class ExpResCriterion_DNSAnswers(ExpResCriterion_DNSBased):
    """Criterion: dns_answers

    Verify if the responses received by a probe contain the expected
    records.

    Available for: dns.

    `dns_answers`: one or more sections where records are searched on. Must
    be one of "answers", "authorities", "additionals".

    Each section must contain a list of records.

    Match when all the responses received by a probe contain at least one
    record matching the expected ones in each of the given sections.

    Example:

    dns_answers:
        answers:
            - <record1>
            - <record2>
        authorities:
            - <record3>
            - <record4>
    """

    CRITERION_NAME = "dns_answers"
    AVAILABLE_FOR_MSM_TYPE = ["dns"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, cfg, expres):
        ExpResCriterion_DNSBased.__init__(self, cfg, expres)

        self.dns_answers = self._enforce_param("dns_answers", dict)

        self.sections = []

        SECTIONS = ["answers", "authorities", "additionals"]
        for section in self.dns_answers.keys():
            if section.lower() not in SECTIONS:
                raise ConfigError(
                    "Invalid section: {}. Must be one of {}".format(
                        section, ", ".join(SECTIONS)
                    )
                )

            if isinstance(self.dns_answers[section], list):
                section_cfg = self.dns_answers[section]
            elif isinstance(self.dns_answers[section], dict):
                section_cfg = [self.dns_answers[section]]
            else:
                raise ConfigError(
                    "Invalid section {}".format(section)
                )
            self.sections.append(
                ExpResCriterion_AnswersSection(
                    section, section_cfg
                )
            )

    def __str__(self):
        r = ""
        for section in self.sections:
            if r != "":
                r += "; "
            r += "{} section: {}".format(
                section.name,
                ", ".join(map(str, section.records))
            )
        return r

    def prepare_response(self, result, response):
        pass

    def response_matches(self, response):
        for section in self.sections:
            answer_section = getattr(response.abuf, section.name)
            if len(answer_section) == 0:
                logger.debug(
                    "  section {} not found in the response".format(
                        section.name
                    )
                )
                return False

            for record in section.records:
                for answer_record in answer_section:
                    if record.record_matches(answer_record):
                        return True

        return False
