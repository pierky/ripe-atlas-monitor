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

from collections import Counter
from itertools import groupby, combinations, chain
import json

from .Helpers import ProbesFilter
from .MsmProcessingUnit import MsmProcessingUnit
from .ParsedResults import ParsedResult_RTT, ParsedResult_DstResponded, \
                           ParsedResult_DstIP, ParsedResult_CertFps, \
                           ParsedResult_DstAS, ParsedResult_UpstreamAS, \
                           ParsedResult_ASPath, ParsedResult_DNSHeader, \
                           ParsedResult_EDNS, ParsedResult_DNSAnswers
from ripe.atlas.sagan import Result


class BasePropertyAnalyzer(object):
    """BasePropertyAnalyzer

    This class is responsible for aggregating and displaying results
    received from a measurement.

    Given a property of a ParsedResult object, this class takes a list
    of touples (value, probe_id), aggregates the values and produces a
    counter of how many probes reported the value (and also a list of
    them).
    Some tricks are used to produce a shorter list of most common values
    in case the full list is too long.

    The final output is something like this:

    -----------------------------------------------------------------
    Title:

      property_val_XXX: n times, <probe_1>, <probe_2>, <probe_3>, ...

      property_val_YYY: n times, <probe_4>, <probe_5>

       (use the --show-all-PROP argument to show the full list
    -----------------------------------------------------------------

    TITLE is used to print the header.
    Then SHOW_TIMES is True, the "n times" format is used.
    SHOW_PROBE_IDS is the number of probes that are listed beside each
    property's value.
    The SHOW_FULL_LIST_ARG attribute is the string of the command line
    argument used to show the full list (SHOW_FULL_LIST_VAR is the
    corresponding entry in the namespace returned by the argument parser).

    The __init__() method takes the source list (src_list), list of
    touples (value, probe_id). Values can be string, int, list or
    touple.

    The analyze() method calls the get_key_cnt_list() to build a list
    of aggregate results in the form of touples (key, count, probes):
    probes is a list of probe IDs.
    After that, it calls the write_key_cnt_list() to build the final
    output. From the list of touples (key, count, probes) returned by
    get_key_cnt_list() the key is formatted using the format_key()
    method; the whole list is sorted using the sort_key_cnt_list() method
    and finally the output is built.

    The get_key_cnt_list() calls the get_normalized_src_list() to obtain
    a normalized view of the source list. For example, for RTT thresholds
    the get_normalized_src_list is used to return a mapping between the
    measured RTT and the range where it falls in.

    Example:

    RTT     Normalized RTT
    30  ->  "< 40 ms"
    45  ->  "40 - 60 ms"
    70  ->  ">= 70 ms"

    Some properties can list a lot of unique values; to have a shorter
    (an more readable) output, each class can have a SHORT_LIST_CLASS
    attribute pointing to another BasePropertyAnalyzer-derived class that
    implementes an aggregate-and-display mechanism whose goal is to produce
    a shorter view of the most common values.

    Keep this docstring in sync with docs/CONTRIBUTING.rst file.
    """

    TITLE = ""
    SHOW_TIMES = True
    SHORT_LIST_CLASS = None
    SHOW_FULL_LIST_ARG = None
    SHOW_FULL_LIST_VAR = None
    SHOW_PROBE_IDS = 3
    SHOW_UNIQUE_PROBES_CNT = False

    def __init__(self, analyzer, src_list, use_json=False, **kwargs):
        # src_list, list of tuple (property_value, probe_id)
        assert all(isinstance(probe_id, int) for _, probe_id in src_list)

        if self.SHORT_LIST_CLASS:
            # a class can use another BasePropertyAnalyzer class in its
            # SHORT_LIST_CLASS attribute, but only if it's not a
            # SHORT_LIST_CLASS of another class.
            assert self.SHORT_LIST_CLASS.SHORT_LIST_CLASS is None

        self.analyzer = analyzer

        self.src_list = src_list

        self.use_json = use_json

        self.show_full_list = False
        if self.SHOW_FULL_LIST_VAR:
            self.show_full_list = kwargs.get(self.SHOW_FULL_LIST_VAR, False)

    def get_normalized_src_list(self):
        # return list of tuple (property_value, probe)
        return self.src_list

    def get_key_cnt_list(self):
        # return list of tuples (key, cnt, probes)
        # 'cnt' = how many times 'key' is present in self.src_list
        #         values and for which 'probes'

        not_none_list = \
            [(v, prb)
             for v, prb in self.get_normalized_src_list()
             if v not in (None, "", [])]

        if len(not_none_list) == 0:
            return []

        sorted_src_list = sorted(not_none_list, key=lambda x: x[0])

        key_cnt_list = []
        for key, key_prb_list in groupby(sorted_src_list,
                                         key=lambda x: x[0]):
            prb_list = [probe for _, probe in list(key_prb_list)]
            unique_probes = sorted(list(set(prb_list)))
            key_cnt_list.append((key, len(list(prb_list)), unique_probes))

        return key_cnt_list

    @staticmethod
    def format_key(key):
        return str(key) if key is not None else "none"

    @staticmethod
    def sort_key_cnt_list(list_item):
        # list_item = tuple (key, cnt, probes)
        return list_item[1], list_item[0], sorted(list_item[2])

    def write_key_cnt_list(self, key_cnt_list, top_n=None):

        if len(key_cnt_list) == 0:
            return ""

        r = ""
        r += self.TITLE + "\n"
        r += "\n"

        # keys can be splitted on more lines (for a better readability)

        formatted_keys = [self.format_key(k) for k, _, _ in key_cnt_list]

        key_lines = list(chain(*[key.split("\n") for key in formatted_keys]))

        longest_key = max(key_lines, key=len)

        multiline_keys = any(len(k.split("\n")) > 1 for k in formatted_keys)

        if multiline_keys:
            key_tpl = " {key:" + str(len(longest_key)) + "}"
        else:
            key_tpl = " {key:>" + str(len(longest_key)) + "}"

        tpl = ""
        if self.SHOW_TIMES:
            tpl += ": {times} time{times_s}"

        has_probes = any([probes for _, _, probes in key_cnt_list])

        if has_probes and self.SHOW_UNIQUE_PROBES_CNT:
            if self.SHOW_TIMES:
                tpl += " ({unique_probes_cnt} unique probe{unique_probes_s})"
            else:
                tpl += ", {unique_probes_cnt} unique probe{unique_probes_s}"

        if has_probes:
            tpl += ", {probes}{more_probe}"

        tpl += "\n"

        sorted_key_cnt = sorted(key_cnt_list,
                                key=self.sort_key_cnt_list,
                                reverse=True)

        if top_n:
            sorted_key_cnt = sorted_key_cnt[0:top_n]

        for key, cnt, probes in sorted_key_cnt:
            if not has_probes:
                probes = []

            key_first_line = True
            for key_line in self.format_key(key).split("\n"):
                if not key_first_line:
                    r += "\n"
                r += key_tpl.format(key=key_line)
                key_first_line = False

            r += tpl.format(
                times=cnt,
                times_s="s" if cnt > 1 else "",
                probes=", ".join(
                    map(str,
                        map(self.analyzer.get_probe,
                            probes[0:self.SHOW_PROBE_IDS])
                        )
                    ),
                unique_probes_cnt=str(len(probes)) if has_probes else "",
                unique_probes_s="s" if len(probes) > 1 else "",
                more_probe=", ..." if len(probes) > self.SHOW_PROBE_IDS else ""
            )

            r += "\n"

        return r

    def format_json_key(self, key):
        key = self.format_key(key)
        key = ",".join(key.split("\n"))
        return key

    def get_json_key_cnt_list(self, key_cnt_list, top_n=None):
        out_dict = {}
        for key, cnt, probes in key_cnt_list[0:top_n]:
            key = self.format_json_key(key)
            out_dict[key] = {"count": cnt, "probes": probes}
        return out_dict

    def analyze(self):
        key_cnt_list = self.get_key_cnt_list()

        if len(key_cnt_list) <= 10 or self.show_full_list:
            if self.use_json:
                return self.get_json_key_cnt_list(key_cnt_list)
            else:
                return self.write_key_cnt_list(key_cnt_list)

        if self.SHORT_LIST_CLASS:
            short_list_analyzer = self.SHORT_LIST_CLASS(self.analyzer,
                                                        self.src_list)
            r = short_list_analyzer.analyze()
        else:
            if self.use_json:
                return self.get_json_key_cnt_list(key_cnt_list, top_n=10)
            else:
                r = self.write_key_cnt_list(key_cnt_list, top_n=10)
                r += "  Only top 10 most common shown.\n"

        if self.SHOW_FULL_LIST_ARG and not self.use_json:
            r += ("  (use the {} argument "
                  "to show the full list)\n\n").format(
                    self.SHOW_FULL_LIST_ARG)

        return r


class PropertyAnalyzer_RTT_Short(BasePropertyAnalyzer):

    TITLE = "Median RTTs:"

    @staticmethod
    def get_thresholds(rtts_probes):
        if len(rtts_probes) >= 10:
            # exclude highest and lowest 10% of values from thresholds calc
            perc = int(len(rtts_probes) / 100.0 * 10.0)
            rtts_probes_for_calc = sorted(rtts_probes, key=lambda x: x[0])
            rtts_probes_for_calc = rtts_probes_for_calc[perc:-perc]
        else:
            rtts_probes_for_calc = rtts_probes

        min_rtt = int(min([rtt for rtt, _ in rtts_probes_for_calc]))
        max_rtt = int(max([rtt for rtt, _ in rtts_probes_for_calc]))
        increment = int((max_rtt - min_rtt) / 6)
        if increment == 0:
            increment = 1
        thresholds = [min_rtt + increment * (i + 1) for i in range(6)]
        return thresholds

    def get_normalized_src_list(self):
        rtts_probes = [(rtt, prb)
                       for rtt, prb in self.src_list if rtt is not None]

        thresholds = self.get_thresholds(rtts_probes)

        res = []
        for rtt, prb in rtts_probes:
            if rtt < thresholds[0]:
                res.append(("< {} ms".format(thresholds[0]), prb))
            elif rtt >= thresholds[-1]:
                res.append((">= {} ms".format(thresholds[-1]), prb))
            else:
                r = str(rtt)
                for i in range(len(thresholds)-1):
                    if rtt >= thresholds[i] and rtt < thresholds[i+1]:
                        r = "{} - {} ms".format(
                            thresholds[i], thresholds[i+1]
                        )
                        break
                res.append((r, prb))

        return res


class PropertyAnalyzer_RTT(BasePropertyAnalyzer):

    TITLE = "Unique median RTTs:"
    SHOW_TIMES = False
    SHORT_LIST_CLASS = PropertyAnalyzer_RTT_Short
    SHOW_FULL_LIST_ARG = "--show-all-rtts"
    SHOW_FULL_LIST_VAR = "show_full_rtts"

    @staticmethod
    def format_key(key):
        return "{:>7.2f} ms".format(key) if key is not None else "none"

    @staticmethod
    def sort_key_cnt_list(list_item):
        # list_item = tuple (key, cnt, probes)
        return -list_item[0], sorted(list_item[2])


class PropertyAnalyzer_Responded(BasePropertyAnalyzer):

    TITLE = "Destination responded:"

    @staticmethod
    def format_key(key):
        if key is True:
            return "yes"
        elif key is False:
            return "no"
        else:
            return "none"


class PropertyAnalyzer_Dst_IP(BasePropertyAnalyzer):

    TITLE = "Unique destination IP addresses:"


class PropertyAnalyzer_Cer_Fps(BasePropertyAnalyzer):

    TITLE = "Unique SSL certificate fingerprints:"
    SHOW_PROBE_IDS = 2

    @staticmethod
    def format_key(key):
        return "\n".join(key)


class PropertyAnalyzer_Dst_AS(BasePropertyAnalyzer):

    TITLE = "Destination AS:"
    SHOW_FULL_LIST_ARG = "--show-all-dest-asns"
    SHOW_FULL_LIST_VAR = "show_full_destasn"


class PropertyAnalyzer_Upstream_AS(BasePropertyAnalyzer):

    TITLE = "Upstream AS:"
    SHOW_FULL_LIST_ARG = "--show-all-upstream-asns"
    SHOW_FULL_LIST_VAR = "show_full_upstreamasn"


class PropertyAnalyzer_ASPath_Base_Short(BasePropertyAnalyzer):

    def get_key_cnt_list(self):
        # Stolen from http://codereview.stackexchange.com/questions/108052/
        sequences = [as_path
                     for as_path, _ in self.get_normalized_src_list()
                     if as_path != []]
        counter = Counter(seq[i:j]
                          for seq in map(tuple, sequences)
                          for i, j in combinations(range(len(seq) + 1), 2))
        ordered = sorted(
            list(counter.items()),
            key=lambda x: (x[1], len(x[0])),
            reverse=True)
        filtered = [(as_path, cnt, None)
                    for as_path, cnt in ordered if len(as_path) > 1]
        return filtered[0:10]

    @staticmethod
    def format_key(key):
        return " ".join(map(str, key))

    @staticmethod
    def sort_key_cnt_list(list_item):
        # list_item = tuple (key, cnt, probes)
        # probes is None for short AS path list
        return list_item[1], len(list_item[0]), sorted(list_item[0])


class PropertyAnalyzer_ASPath_Base(BasePropertyAnalyzer):

    SHOW_FULL_LIST_ARG = "--show-all-aspaths"
    SHOW_FULL_LIST_VAR = "show_full_aspaths"

    @staticmethod
    def format_key(key):
        return " ".join(map(str, key))

    @staticmethod
    def sort_key_cnt_list(list_item):
        # list_item = tuple (key, cnt, probes)
        return list_item[1], len(list_item[0]), sorted(list_item[0]), \
               sorted(list_item[2])


class PropertyAnalyzer_ASPath_Short(PropertyAnalyzer_ASPath_Base_Short):

    TITLE = "Most common ASs sequences:"


class PropertyAnalyzer_ASPath(PropertyAnalyzer_ASPath_Base):

    TITLE = "Unique AS paths:"
    SHORT_LIST_CLASS = PropertyAnalyzer_ASPath_Short


class PropertyAnalyzer_ASPath_IXP_Short(PropertyAnalyzer_ASPath_Base_Short):

    TITLE = "Most common ASs sequences (with IXPs networks):"

    def get_normalized_src_list(self):
        return [(path, probe) for path, probe in self.src_list if "IX" in path]


class PropertyAnalyzer_ASPath_IXP(PropertyAnalyzer_ASPath_Base):

    TITLE = "Unique AS paths (with IXPs networks):"
    SHORT_LIST_CLASS = PropertyAnalyzer_ASPath_IXP_Short

    def get_normalized_src_list(self):
        return [(path, probe) for path, probe in self.src_list if "IX" in path]


class PropertyAnalyzer_Flags(BasePropertyAnalyzer):

    TITLE = "Unique DNS flags combinations:"

    @staticmethod
    def format_key(key):
        return ", ".join(map(str, sorted(key)))


class PropertyAnalyzer_RCode(BasePropertyAnalyzer):

    TITLE = "Unique DNS rcodes:"
    SHOW_UNIQUE_PROBES_CNT = True


class PropertyAnalyzer_EDNS(BasePropertyAnalyzer):

    TITLE = "EDNS present:"
    SHOW_UNIQUE_PROBES_CNT = True

    @staticmethod
    def format_key(key):
        if key is True:
            return "yes"
        elif key is False:
            return "no"
        else:
            return "none"


class PropertyAnalyzer_EDNS_Size(BasePropertyAnalyzer):

    TITLE = "EDNS size:"
    SHOW_UNIQUE_PROBES_CNT = True


class PropertyAnalyzer_EDNS_DO(BasePropertyAnalyzer):

    TITLE = "EDNS DO flag:"
    SHOW_UNIQUE_PROBES_CNT = True

    @staticmethod
    def format_key(key):
        if key is True:
            return "yes"
        elif key is False:
            return "no"
        else:
            return "none"


class PropertyAnalyzer_EDNS_NSID(BasePropertyAnalyzer):

    TITLE = "EDNS NSID:"
    SHOW_FULL_LIST_ARG = "--show-all-edns-nsid"
    SHOW_FULL_LIST_VAR = "show_full_edns_nsid"
    SHOW_UNIQUE_PROBES_CNT = True


class PropertyAnalyzer_DNSAnswers(BasePropertyAnalyzer):

    TITLE = "DNS Answers:"
    SHOW_FULL_LIST_ARG = "--show-all-dns-answers"
    SHOW_FULL_LIST_VAR = "show_full_dns_answers"
    SHOW_PROBE_IDS = 2
    SHOW_UNIQUE_PROBES_CNT = True

    @staticmethod
    def format_key(key):
        lines = []
        for name, _type, value in key:
            lines.append("{:25} {:6} {:15}".format(
                name, _type, value))
        return "\n".join(lines)

    def format_json_key(self, key):
        lines = []
        for name, _type, value in key:
            lines.append("{};{},{}".format(
                name, _type, value))
        return ",".join(lines)


class BaseResultsAnalyzer(object):
    """BaseResultsAnalyzer

    This class is used to analyze all the properties of each element of a
    result.

    A result may have some "subparts", like DNS responses:

      "DNS measurement results are a little wacky. Sometimes you get a single
      response, other times you get a set of responses (result set). In order
      to establish a unified interface, we conform all results to the same
      format: a list of response objects."

      (https://github.com/RIPE-NCC/ripe.atlas.sagan/blob/
       893f7f5fefc0101294c95beb210a92e164c39e5f/ripe/atlas/sagan/dns.py#L742)

    The get_parsed_results() method yield touples of
    (<ParsedResult object>, <probe ID>) for each result's element; these
    ParsedResult objects are used by the analyze() method to gather all the
    available properties and organize them in list of touples (property value,
    probe ID), one list for each property. Each property is finally analyzed
    using the related BasePropertyAnalyzer-derived class.

    Keep this docstring in sync with docs/CONTRIBUTING.rst file.
    """

    PARSED_RESULTS_CLASS = None
    PROPERTIES_ANALYZERS_CLASSES = {
        "rtt": PropertyAnalyzer_RTT,
        "responded": PropertyAnalyzer_Responded,
        "dst_ip": PropertyAnalyzer_Dst_IP,
        "cer_fps": PropertyAnalyzer_Cer_Fps,
        "dst_as": PropertyAnalyzer_Dst_AS,
        "upstream_as": PropertyAnalyzer_Upstream_AS,
        "as_path": PropertyAnalyzer_ASPath,
        "as_path_ixps": PropertyAnalyzer_ASPath_IXP,
        "flags": PropertyAnalyzer_Flags,
        "rcode": PropertyAnalyzer_RCode,
        "edns": PropertyAnalyzer_EDNS,
        "edns_size": PropertyAnalyzer_EDNS_Size,
        "edns_do": PropertyAnalyzer_EDNS_DO,
        "edns_nsid": PropertyAnalyzer_EDNS_NSID,
        "dns_answers": PropertyAnalyzer_DNSAnswers
    }
    PROPERTIES_ORDER = ["rtt", "responded", "dst_ip", "cer_fps", "dst_as",
                        "upstream_as", "as_path", "as_path_ixps", "rcode",
                        "flags", "edns", "edns_size", "edns_do", "edns_nsid",
                        "dns_answers"]

    def __init__(self, analyzer, results, **kwargs):
        self.analyzer = analyzer

        self.use_json = kwargs.get("use_json", False)

        self.results = results  # Result objects

        self.kwargs = kwargs

        self.props = {}  # property_name: [(property_val, probe_id), ...]

    def get_parsed_results(self):
        for result in self.results:
            yield (
                self.PARSED_RESULTS_CLASS(self.analyzer, result),
                result.probe_id
            )

    def analyze(self):
        for parsed_result, probe_id in self.get_parsed_results():
            try:
                parsed_result.prepare()
            except NotImplementedError:
                continue

            for prop in parsed_result.PROPERTIES:
                if prop not in self.props:
                    self.props[prop] = []
                self.props[prop].append(
                    (getattr(parsed_result, prop), probe_id)
                )

        text = ""
        json_object = {}

        for prop in self.PROPERTIES_ORDER:
            if prop not in self.PROPERTIES_ANALYZERS_CLASSES:
                raise NotImplementedError()
            if prop not in self.props:
                continue
            prop_analyzer_class = self.PROPERTIES_ANALYZERS_CLASSES[prop]
            prop_analyzer = prop_analyzer_class(self.analyzer,
                                                self.props[prop],
                                                **self.kwargs)

            if self.use_json:
                json_object[prop] = prop_analyzer.analyze()
            else:
                text += prop_analyzer.analyze()

        if self.use_json:
            return json_object
        else:
            return text


class ResultsAnalyzer_RTT(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_RTT


class ResultsAnalyzer_DstResponded(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_DstResponded


class ResultsAnalyzer_DstIP(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_DstIP


class ResultsAnalyzer_CertFps(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_CertFps


class ResultsAnalyzer_DstAS(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_DstAS


class ResultsAnalyzer_UpstreamAS(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_UpstreamAS


class ResultsAnalyzer_ASPath(BaseResultsAnalyzer):

    PARSED_RESULTS_CLASS = ParsedResult_ASPath


class ResultsAnalyzer_DNSBased(BaseResultsAnalyzer):

    def get_parsed_results(self):
        for result in self.results:
            try:
                for response in result.responses:
                    if response.abuf:
                        yield (
                            self.PARSED_RESULTS_CLASS(
                                self.analyzer, result, response),
                            result.probe_id
                        )
            except AttributeError:
                return


class ResultsAnalyzer_DNSHeader(ResultsAnalyzer_DNSBased):

    PARSED_RESULTS_CLASS = ParsedResult_DNSHeader


class ResultsAnalyzer_EDNS(ResultsAnalyzer_DNSBased):

    PARSED_RESULTS_CLASS = ParsedResult_EDNS


class ResultsAnalyzer_DNSAnswers(ResultsAnalyzer_DNSBased):

    PARSED_RESULTS_CLASS = ParsedResult_DNSAnswers


class Analyzer(MsmProcessingUnit):

    RESULTS_ANALYZERS = [ResultsAnalyzer_RTT, ResultsAnalyzer_DstResponded,
                         ResultsAnalyzer_DstIP, ResultsAnalyzer_CertFps,
                         ResultsAnalyzer_DstAS, ResultsAnalyzer_UpstreamAS,
                         ResultsAnalyzer_ASPath, ResultsAnalyzer_DNSHeader,
                         ResultsAnalyzer_EDNS, ResultsAnalyzer_DNSAnswers]

    def analyze(self, probes_filter=None, **kwargs):
        cc_threshold = kwargs.get("cc_threshold", 3)
        top_countries = kwargs.get("top_countries", 0)
        as_threshold = kwargs.get("as_threshold", 3)
        top_asns = kwargs.get("top_asns", 0)
        show_stats = kwargs.get("show_stats", False)

        self.use_json = kwargs.get("use_json", False)

        if not self.use_json and not kwargs.get("unittest", False):
            print("Downloading and processing results... please wait")

        if not probes_filter:
            probes_filter = ProbesFilter()

        json_results = self.download(latest_results=True,
                                     probe_ids=probes_filter.probe_ids)
        self.update_probes(json_results)

        results = []
        probe_ids = []

        for result in json_results:
            result = Result.get(result, on_error=Result.ACTION_IGNORE,
                                on_malformation=Result.ACTION_IGNORE)
            probe = self.get_probe(result)
            if probe not in probes_filter:
                continue

            results.append(result)
            if result.probe_id not in probe_ids:
                probe_ids.append(result.probe_id)

        r = self.analyze_results(results, **kwargs)

        ccs = {}
        asns = {}

        for id in probe_ids:
            prb = self.get_probe(id)

            if prb.country_code:
                if prb.country_code not in ccs:
                    ccs[prb.country_code] = []
                ccs[prb.country_code].append(id)

            if prb.asn:
                if prb.asn not in asns:
                    asns[prb.asn] = []
                asns[prb.asn].append(id)

        probes_per_country = sorted({
            cc: lst for cc, lst in ccs.items() if len(lst) > cc_threshold
        }.items(), key=lambda x: (-len(x[1]), x[0]))
        probes_per_src_asn = sorted({
            asn: lst for asn, lst in asns.items() if len(lst) > as_threshold
        }.items(), key=lambda x: (-len(x[1]), x[0]))

        if show_stats:
            r += "Statistics:\n"
            r += "\n"

            r += " - {} unique probes found\n".format(len(probe_ids))

            if len(probes_per_country) > 0:
                tpl = " - countries with more than {} probe{}:\n"
            else:
                tpl = " - no countries with more than {} probe{}\n"
            r += tpl.format(cc_threshold, "s" if cc_threshold > 1 else "")

            for cc, probes in probes_per_country:
                r += "   - {}: {} probes\n".format(cc, len(probes))

            if len(probes_per_src_asn) > 0:
                tpl = " - source ASNs with more than {} probe{}:\n"
            else:
                tpl = " - no source ASNs with more than {} probe{}\n"
            r += tpl.format(as_threshold, "s" if as_threshold > 1 else "")

            for asn, probes in probes_per_src_asn:
                r += "   - {:>7}: {} probes\n".format(asn, len(probes))

            r += "\n"

        def top_most(lst, tpl, top_cnt):
            r = ""
            for k, probes in sorted(lst[:top_cnt], key=lambda x: x[0]):
                r += "\n\n\n"
                r += tpl.format(k=k, n=len(probes))
                r += "\n"

                r += self.analyze_results(
                    [res for res in results if res.probe_id in probes],
                    **kwargs
                )
            return r

        if top_countries and len(probes_per_country) > 0:
            r += top_most(probes_per_country,
                          "Analyzing results from {k} ({n} probes)...\n",
                          top_countries)

        if top_asns and len(probes_per_src_asn) > 0:
            r += top_most(probes_per_src_asn,
                          "Analyzing results from AS{k} ({n} probes)...\n",
                          top_asns)
        return r

    def analyze_results(self, results, **kwargs):
        r = ""

        if len(results) == 0:
            return r

        json_object = {}

        for c in self.RESULTS_ANALYZERS:
            results_analyzer = c(self, results, **kwargs)
            if self.use_json:
                key = c.__name__.replace("ResultsAnalyzer_", "")
                json_out = results_analyzer.analyze()
                if json_out:
                    json_object[key] = json_out
            else:
                r += results_analyzer.analyze()

        if self.use_json:
            r = json.dumps(json_object, ensure_ascii=True, allow_nan=False,
                           indent=2)
        return r
