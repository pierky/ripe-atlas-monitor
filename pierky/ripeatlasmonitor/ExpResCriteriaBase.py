from Errors import ConfigError
from Helpers import BasicConfigElement


class ExpResCriterion(BasicConfigElement):
    CRITERION_NAME = None
    AVAILABLE_FOR_MSM_TYPE = []
    OPTIONAL_CFG_FIELDS = []
    MANDATORY_CFG_FIELDS = []

    @classmethod
    def get_cfg_fields(cls):
        m = set(cls.MANDATORY_CFG_FIELDS)
        o = set(cls.OPTIONAL_CFG_FIELDS)

        if cls.CRITERION_NAME:
            m.add(cls.CRITERION_NAME)

        return m, o

    def __init__(self, cfg, expres):
        if self.CRITERION_NAME is None:
            raise NotImplementedError()
        if len(self.AVAILABLE_FOR_MSM_TYPE) == 0:
            raise NotImplementedError()

        BasicConfigElement.__init__(self, cfg)

        self.monitor = expres.monitor
        self.expres = expres

        if self.monitor.msm_type not in self.AVAILABLE_FOR_MSM_TYPE:
            raise ConfigError(
                "Can't use {} for this measurement; "
                "it is available only on {}.".format(
                    self.CRITERION_NAME, ", ".join(self.AVAILABLE_FOR_MSM_TYPE)
                )
            )

    @staticmethod
    def get_parsed_res_key(result, prb_id):
        return "{}-{}".format(prb_id, result.created)

    def get_parsed_res(self, result, prb_id, param):
        k = self.get_parsed_res_key(result, prb_id)

        if k in self.monitor.parsed_res:
            if param in self.monitor.parsed_res[k]:
                return self.monitor.parsed_res[k][param]
        return None

    def set_parsed_res(self, result, prb_id, param, val):
        k = self.get_parsed_res_key(result, prb_id)

        if k not in self.monitor.parsed_res:
            self.monitor.parsed_res[k] = {}
        self.monitor.parsed_res[k][param] = val

    def prepare(self, result):           # pragma: no cover
        # Called before result_matches().
        # It can be used to parse results and store the new internal
        # data structures only once.
        # For example, the TracerouteBased criteria use this to build
        # AS path only once for each result/probe and store it in the
        # parsed_res cache; the first _TracerouteBased criterion
        # builds the path and store it using set_parsed_res, the following
        # criteria find the path already built and reuse it.
        pass

    def parse_data(self, result):        # pragma: no cover
        # Called by prepare() when no parsed data are present
        # in the cache.
        pass

    def result_matches(self, result):    # pragma: no cover
        raise NotImplementedError()

    def __str__(self):                          # pragma: no cover
        raise NotImplementedError()

    def _str_list(self):
        if hasattr(self, self.CRITERION_NAME):
            return ", ".join(map(str, getattr(self, self.CRITERION_NAME)))
        else:
            raise NotImplementedError()         # pragma: no cover

    def display_string(self):                   # pragma: no cover
        return "    - {}".format(str(self))
