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

from .ExpResCriteriaCommon import ExpResCriterion_RTT, \
                                  ExpResCriterion_DstResponded, \
                                  ExpResCriterion_DstIP
from .ExpResCriteriaTraceroute import ExpResCriterion_DstAS, \
                                      ExpResCriterion_ASPath, \
                                      ExpResCriterion_UpstreamAS
from .ExpResCriteriaSSL import ExpResCriterion_CertFP
from .ExpResCriteriaDNS import ExpResCriterion_DNSFlags, \
                               ExpResCriterion_DNSRCode, \
                               ExpResCriterion_EDNS, \
                               ExpResCriterion_DNSAnswers


CRITERIA_CLASSES_COMMON = [
    ExpResCriterion_RTT,
    ExpResCriterion_DstResponded,
    ExpResCriterion_DstIP
]

CRITERIA_CLASSES_TRACEROUTE = [
    ExpResCriterion_DstAS,
    ExpResCriterion_ASPath,
    ExpResCriterion_UpstreamAS,
]

CRITERIA_CLASSES_SSL = [
    ExpResCriterion_CertFP,
]

CRITERIA_CLASSES_DNS = [
    ExpResCriterion_DNSRCode,
    ExpResCriterion_DNSFlags,
    ExpResCriterion_EDNS,
    ExpResCriterion_DNSAnswers
]

CRITERIA_CLASSES = \
    CRITERIA_CLASSES_COMMON + \
    CRITERIA_CLASSES_TRACEROUTE + \
    CRITERIA_CLASSES_SSL + \
    CRITERIA_CLASSES_DNS
