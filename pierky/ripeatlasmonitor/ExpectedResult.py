from .Errors import ConfigError, ResultProcessingError
from .ExpResCriteria import CRITERIA_CLASSES
from .Helpers import BasicConfigElement
from .Logging import logger


class ExpectedResult(BasicConfigElement):
    """Expected result

    A group of criteria used to match probes' results.

    `descr` (optional): a brief description of this group of criteria.

    Matching rules reference this on their `expected_results` list.

    When a probe matches a rule, the keys in the `expected_results` list
    of that rule are used to obtain the group of criteria to be used to
    process the result.

    Example:

    matching_rules:
    - descr: Probes from France via AS64496
      src_country: FR
      expected_results: ViaAS64496
    expected_results:
      ViaAS64496:
        upstream_as: 64496
    """

    OPTIONAL_CFG_FIELDS = ["descr"]
    MANDATORY_CFG_FIELDS = []

    @classmethod
    def get_cfg_fields(cls):
        m = set(cls.MANDATORY_CFG_FIELDS)
        o = set(cls.OPTIONAL_CFG_FIELDS)

        for criterion_class in CRITERIA_CLASSES:
            o.update(criterion_class.get_all_cfg_fields())

        return m, o

    def __init__(self, monitor, name, cfg):
        BasicConfigElement.__init__(self, cfg)

        self.monitor = monitor

        self.name = name
        self.normalize_fields()

        self.descr = cfg["descr"]

        self.criteria = []

        for criterion_class in CRITERIA_CLASSES:
            if self.cfg[criterion_class.CRITERION_NAME] is not None:
                self.criteria.append(criterion_class(self.cfg, self))

        if len(self.criteria) == 0:
            raise ConfigError("No criteria found.")

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            ret = []
            for criterion in self.criteria:
                ret.append(str(criterion))
            if len(ret) > 0:
                return "; ".join(ret)
            else:
                return "No expected results"

    def display(self):
        if self.descr:
            print("    {}: {}".format(self.name, self.descr))
        else:
            print("    {}".format(self.name))

        for criterion in self.criteria:
            print(criterion.display_string())

        print("")

    def result_matches(self, result):
        # result is a ripe.atlas.sagan result

        probe = self.monitor.get_probe(result)

        result_descr = "{}, {}".format(probe, result.created)

        for criterion in self.criteria:
            try:
                criterion.prepare(result)
                if not criterion.result_matches(result):
                    return False
            except ResultProcessingError as e:
                logger.warning(
                    "Error processing result {}: {}".format(
                        result_descr, str(e)
                    )
                )
                return False

        return True
