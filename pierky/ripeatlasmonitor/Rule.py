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


from .Errors import ConfigError, RIPEAtlasMonitorError
from .Helpers import BasicConfigElement
from .Logging import logger


class Rule(BasicConfigElement):
    """Rule

    Probes which produced the results fetched from the measurement are matched
    against these rules to determine whether those results must be processed
    or not.

    `descr` (optional): a brief description of the rule.

    `process_next` (optional): determine whether the rule following the current
    one has to be elaborated or nor. More details on the description below.

    `src_country` (optional): list of two letters country ISO codes.

    `src_as` (optional): list of Autonomous System numbers.

    `probe_id` (optional): list of probes' IDs.

    `internal_labels` (optional): list of internal labels. More details on the
    description below.

    `reverse` (optional): boolean, indicating if the aforementioned criteria
    identify probes which have to be exluded from the matching.

    `expected_results` (optional): list of expected results' names which
    have to be processed on match. Must be one or more of the expected results
    defined in Monitor.`expected_results`. If empty or missing, the rule will
    be treated as if a match occurred and its actions are performed.

    `actions` (optional): list of actions' names which have to be perormed for
    matching probes. Must be one or more of the actions defined in
    Monitor.`actions`.

    The `src_country` criterion matches when probe's source country is one of
    the country ISO codes given in the list.

    The `src_as` criterion matches when probe's source AS is one of the ASN
    given in the list. Since RIPE Atlas defines two ASs for each probe (ASN_v4
    and ASN_v6) the one corresponding to the measurement's address family is
    taken into account.

    The `probe_id` criterion matches when probe's ID is one of the IDs given
    in the list.

    The `internal_labels` criterion matches when a probe has been previously
    tagged with a label falling in the given list. See the `label` Action for
    more details.

    A probe matches the rule when all the given criteria are satisfied or when
    no criteria are defined at all. If `reverse` is True, a probe matches when
    none of the criteria is satisfied.

    When a probe matches the rule, the expected results given
    in `expected_results` are processed; actions given in the `actions` list
    are performed on the basis of expected results processing output. If
    no `expected_results` are given, actions will be performed too.

    When a probe matches the current rule's criteria:

    - if `process_next` is True, the rule which follows the current one is
      forcedly elaborated;

    - if `process_next` if False or missing, the rules processing is stopped.

    If a probe does not match the current rule's criteria:

    - if `process_next` is False, the rule processing is forcedly stopped;

    - if `process_next` is True or missing, the rule which follows the current
      one is regularly processed.

    Examples:

    matching_rules:
    - descr: Do not process results for probe ID 123 and 456
      probe_id:
      - 123
      - 456
    - descr: Check dst AS for any probe, errors to NOC; process next rule
      expected_results: DstAS
      actions: SendEMailToNOC
      process_next: True
    - descr: Italian probes must reach target via AS64496
      src_country: IT
      expected_results: ViaAS64496
      actions: LogErrors
    - descr: German and French probes must reach target with low RTT
      src_country:
      - DE
      - FR
      expected_results: LowRTT
      actions: LogErrors

    matching_rules:
    - descr: Set 'VIP' (Very Important Probe) label to ID 123 and 456
      probe_id:
      - 123
      - 456
      process_next: True
      actions: SetVIPLabel
    - descr: Set 'VIP' label to Italian probes too
      src_country: IT
      process_next: True
      actions: SetVIPLabel
    - descr: VIPs must have low RTT
      internal_labels: VIP
      expected_results: LowRTT
    """

    MANDATORY_CFG_FIELDS = []

    OPTIONAL_CFG_FIELDS = ["expected_results", "descr", "process_next",
                           "src_country", "src_as", "probe_id", "reverse",
                           "internal_labels", "actions"]

    def __init__(self, monitor, cfg):
        BasicConfigElement.__init__(self, cfg)

        self.monitor = monitor

        self.normalize_fields()

        self.descr = cfg["descr"]

        self.process_next = self._enforce_param("process_next", bool)

        self.src_country = self._enforce_list("src_country", str)

        self.src_as = self._enforce_list("src_as", int)

        self.probe_id = self._enforce_list("probe_id", int)

        self.internal_labels = self._enforce_list("internal_labels", str)

        self.reverse = self._enforce_param("reverse", bool) or False

        self.expected_results = self._enforce_list("expected_results", str)

        if self.expected_results is None:
            self.expected_results = []

        self.actions = self._enforce_list("actions", str)

        if self.src_country:
            for cc in self.src_country:
                if not re.match(r"^[a-zA-Z][a-zA-Z]$", cc):
                    raise ConfigError(
                        "Invalid country code: {}. "
                        "Countries must be defined with a two-letter "
                        "ISO code.".format(cc)
                    )

    def _str_src_county(self):
        return ", ".join(self.src_country)

    def _str_src_as(self):
        return ", ".join(map(str, self.src_as))

    def _str_probe_id(self):
        return ", ".join(map(str, self.probe_id))

    def _str_internal_labels(self):
        return ", ".join(self.internal_labels)

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            ret = []
            if self.reverse:
                ret.append("Reverse")
            if len(self.src_country) > 0:
                ret.append("Country: {}".format(self._str_src_county()))
            if len(self.src_as) > 0:
                ret.append("Source AS: {}".format(self._str_src_as()))
            if len(self.probe_id) > 0:
                ret.append("Probe ID: {}".format(self._str_probe_id()))
            if len(self.internal_labels) > 0:
                ret.append("Internal labels: {}".format(
                    self._str_internal_labels())
                )
            if len(ret) > 0:
                return "; ".join(ret)
            else:
                return "Match any probe"

    def display(self):
        criteria_found = 0

        if self.descr:
            print("  Description  : {}".format(self.descr))
            print("")

        if self.reverse:
            print("  Reverse      : {}".format(self.reverse))

        if len(self.src_country) > 0:
            criteria_found += 1
            print("  Country      : {}".format(self._str_src_county()))

        if len(self.src_as) > 0:
            criteria_found += 1
            print("  Source AS    : {}".format(self._str_src_as()))

        if len(self.probe_id) > 0:
            criteria_found += 1
            print("  Probe ID     : {}".format(self._str_probe_id()))

        if len(self.internal_labels) > 0:
            criteria_found += 1
            print("  Internal labels: {}".format(self._str_internal_labels()))

        if criteria_found > 1:
            print("")
            print(
                "  The rule matches for source probes that {}satisfy all the "
                "above criteria.".format("do not " if self.reverse else "")
            )
        elif criteria_found == 1:
            print("")
            print(
                "  The rule matches for source probes that {}satisty the "
                "above criterion.".format("do not " if self.reverse else "")
            )
        else:
            print(
                "  No criteria defined for the rule: it {}  matches for "
                "any source probe.".format(
                    "never " if self.reverse else "always"
                )
            )

        print("")
        if self.process_next:
            if self.process_next is True:
                print(
                    "  The rules following this one are processed even if a "
                    "matching condition is found."
                )
            else:
                print(
                    "  If a matching condition is not found, the rule that "
                    "follows this one is not elaborated and the rules "
                    "processing is forcedly stopped."
                )
        else:
            print(
                "  If a matching condition is not found, the rule that "
                "follows this one is elaborated."
            )
            print(
                "  Once a matching condition is found, the rules following "
                "this one are not processed and the execution is stopped."
            )

        print("")

    def probe_matches(self, probe):
        criteria_cnt = 0
        match_cnt = 0

        if self.reverse:
            logger.debug("  excluding rule!")

        if len(self.src_country) > 0:
            criteria_cnt += 1
            logger.debug(
                "  testing probe ID {}: "
                "country [{}] in {}".format(probe.id, probe.country_code,
                                            self._str_src_county())
            )
            if probe.country_code in self.src_country:
                match_cnt += 1

        if len(self.src_as) > 0:
            criteria_cnt += 1
            logger.debug(
                "  testing probe ID {}: "
                "src AS [{}] in {}".format(
                    probe.id,
                    probe.asn,
                    self._str_src_as())
            )
            if probe.asn in self.src_as:
                match_cnt += 1

        if len(self.probe_id) > 0:
            criteria_cnt += 1
            logger.debug("  testing probe ID {}: ID in {}".format(
                probe.id, self._str_probe_id())
            )
            if probe.id in self.probe_id:
                match_cnt += 1

        if len(self.internal_labels) > 0:
            criteria_cnt += 1
            probe_labels = set()
            for scope in ["probes", "results"]:
                if str(probe.id) in self.monitor.internal_labels[scope]:
                    probe_labels.update(
                        self.monitor.internal_labels[scope][str(probe.id)]
                    )
            logger.debug(
                "  testing probe ID {}: "
                "internal labels: {}, expected labels: {}".format(
                    probe.id,
                    ", ".join(probe_labels) if probe_labels else "none",
                    self._str_internal_labels()
                )
            )
            for label in self.internal_labels:
                if label in probe_labels:
                    match_cnt += 1
                    break

        if self.reverse:
            if criteria_cnt == 0:
                logger.debug(
                    "  excluding rule: probe did not pass because "
                    "no criteria are defined for this rule"
                )
                return False
            elif criteria_cnt == match_cnt:
                logger.debug(
                    "  excluding rule: probe did not pass because "
                    "it matched all the criteria for this rule"
                )
                return False
            else:
                return True
        else:
            return criteria_cnt == match_cnt

    def perform_actions(self, result=None, expres=None, result_matches=None):
        for action_name in self.actions:
            action = self.monitor.actions[action_name]

            if action.when == "always" or \
                    (action.when == "on_match" and result_matches is None) or \
                    (action.when == "on_match" and result_matches is True) or \
                    (action.when == "on_mismatch" and result_matches is False):

                try:
                    action.perform(result, expres, result_matches)
                except RIPEAtlasMonitorError as e:
                    logger.error(
                        "Error while performing action '{}': {}".format(
                            str(action), str(e)
                        )
                    )
