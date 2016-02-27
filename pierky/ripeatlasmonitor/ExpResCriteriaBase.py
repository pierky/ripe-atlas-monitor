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

from .Errors import ConfigError
from .Helpers import BasicConfigElement


class ExpResCriterion(BasicConfigElement):
    """ExpResCriterion

    This class reads expected result attributes from the monitor's config
    file, validates them and use them to match received results against
    expected values.

    The CRITERION_NAME contains the main attribute on which this class
    is based.
    The AVAILABLE_FOR_MSM_TYPE list contains all the measurements' types
    for which this expected result can be used ("ping", "traceroute", ...).
    The OPTIONAL_CFG_FIELDS list contains a list of optional attributes that
    can be used in the matching process.
    The MANDATORY_CFG_FIELDS list contains a list of mandatory arguments
    needed to process the results matching. The CRITERION_NAME is implicitly
    part of this list.

    The __init__() method must be used to read and validate each attribute.

    The prepare() method is called before the result_matches() method and is
    used to parse received results.

    The result_matches() is used to determine whether the received result
    matched the expected values.

    The __str__() and display_string() methods are used to print a brief
    description of this expected result and a more detailed description
    to be used when displaying the monitor configuration in a textual form.

    Keep this docstring in sync with docs/CONTRIBUTING.rst file.
    """

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

    def prepare(self, result):           # pragma: no cover
        # Called before result_matches().
        # It can be used to parse results and store the new internal
        # data structures only once.
        # For example, the TracerouteBased criteria use this to build
        # AS path only once for each result/probe and store it in the
        # parsed_res cache; the first _TracerouteBased criterion
        # builds the path and store it using set_parsed_res, the following
        # criteria find the path already built and reuse it.
        raise NotImplementedError()

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
