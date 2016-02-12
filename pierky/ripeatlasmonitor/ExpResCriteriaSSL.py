import re

from Errors import ConfigError
from ExpResCriteriaBase import ExpResCriterion
from Logging import logger
from ParsedResults import ParsedResult_CertFps


class ExpResCriterion_CertFP(ExpResCriterion):
    """Criterion: cert_fp

    Verify SSL certificates' fingerprints.

    Available for: sslcert

    `cert_fp`: list of certificates' SHA256 fingerprints or SHA256
    fingerprints of the chain.

    A fingerprint must be in the format 12:34:AB:CD:EF:... 32 blocks of 2
    characters hex values separated by colon (":").

    The `cert_fp` parameter can contain stand-alone fingerprints or bundle of
    fingerprints in the format "fingerprint1,fingerprint2,fingerprintN".

    A result matches if any of its certificates' fingerprint is in the list
    of stand-alone expected fingerprints or if the full chain fingerprints is
    in the list of bundle fingerprints.

    Examples:

    expected_results:
      MatchLeafCertificate:
        cert_fp: 01:02:[...]:31:32
      MatchLeacCertificates:
        cert_fp:
        - 01:02:[...]:31:32
        - 12:34:[...]:CD:EF
      MatchLeafOrChain:
        cert_fp:
        - 01:02:[...]:31:32
        - 12:34:[...]:CD:EF,56:78:[...]:AB:CD
    """

    CRITERION_NAME = "cert_fp"
    AVAILABLE_FOR_MSM_TYPE = ["sslcert"]
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    FP_PATTERN = re.compile("^[0-9A-F]{2}(:[0-9A-F]{2}){31}$",
                            flags=re.IGNORECASE)

    def _validate_fp(self, v):
        # v can be str or list
        if isinstance(v, str):
            fp = v

            if self.FP_PATTERN.match(fp):
                return fp.upper()
            else:
                raise ConfigError(
                    "Invalid SHA256 fingerprint for cert_fp: {}. "
                    "It must be in the format "
                    "12:34:AB:CD:EF:...[,56:78:9A...]: ".format(
                        fp
                    )
                )
        elif isinstance(v, list):
            ret = []
            for fp in v:
                ret.append(self._validate_fp(fp))
            return ret
        else:
            raise ConfigError(
                "Invalid type for fp: {}".format(type(fp))
            )

    def __init__(self, cfg, expres):
        ExpResCriterion.__init__(self, cfg, expres)

        # list of stand-alone fingerprints or chain of fps
        # [ fp1, fp2, [fp3, fp4] ]
        # will be converted in self.standalone_fps and self.chain_fps
        # a match occurs when
        # - at least one certificate's fp == a stand-alone fp
        # - all the certificates' fps == a chain of fps
        self.cert_fp = self._enforce_list("cert_fp", str)

        self.standalone_fps = []
        self.chain_fps = []

        for fp in self.cert_fp:
            if "," in fp:
                self.chain_fps.append(self._validate_fp(fp.split(",")))
            else:
                self.standalone_fps.append(self._validate_fp(fp))

    def __str__(self):
        return "Certificate SHA256 fingerpring: {}".format(
            self._str_list()
        )

    @staticmethod
    def _str_fp(s):
        return "{}:[...]:{}".format(
            ":".join(s.split(":")[0:2]),
            ":".join(s.split(":")[-2:])
        )

    def _str_list(self):
        res = []
        for fp in self.standalone_fps:
            res.append(self._str_fp(fp))
        for chain in self.chain_fps:
            res.append(
                "({})".format(
                    ", ".join(map(self._str_fp, chain))
                )
            )
        return ", ".join(res)

    def display_string(self):
        more_than_one = len(self.cert_fp) > 1
        return(
            "    - certificate SHA256 fingerprint must be {}the following: "
            "{}".format(
                "one of " if more_than_one else "",
                self._str_list()
            )
        )

    def prepare(self, result):
        res = ParsedResult_CertFps(self.expres.monitor, result)
        self.res_cer_fps = res.cer_fps

    def result_matches(self, result):
        cer_fps = self.res_cer_fps

        logger.debug(
            "  verifying if certificates fingerprints {} in {}...".format(
                ", ".join(cer_fps), self._str_list()
            )
        )

        for cer in result.certificates:
            if cer.checksum_sha256.upper() in self.standalone_fps:
                return True

        for chain in self.chain_fps:
            if sorted(cer_fps) == sorted(chain):
                return True

        return False
