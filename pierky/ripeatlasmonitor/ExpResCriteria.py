from .ExpResCriteriaCommon import ExpResCriterion_RTT, \
                                  ExpResCriterion_DstResponded, \
                                  ExpResCriterion_DstIP
from .ExpResCriteriaTraceroute import ExpResCriterion_DstAS, \
                                      ExpResCriterion_ASPath, \
                                      ExpResCriterion_UpstreamAS
from .ExpResCriteriaSSL import ExpResCriterion_CertFP
from .ExpResCriteriaDNS import ExpResCriterion_DNSFlags, \
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
    ExpResCriterion_DNSFlags,
    ExpResCriterion_EDNS,
    ExpResCriterion_DNSAnswers
]

CRITERIA_CLASSES = \
    CRITERIA_CLASSES_COMMON + \
    CRITERIA_CLASSES_TRACEROUTE + \
    CRITERIA_CLASSES_SSL + \
    CRITERIA_CLASSES_DNS
