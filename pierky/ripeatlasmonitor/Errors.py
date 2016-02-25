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

from traceback import format_exc


class RIPEAtlasMonitorError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class InvalidDateTimeError(RIPEAtlasMonitorError):
    pass


class MissingFileError(RIPEAtlasMonitorError):
    def __init__(self, path):
        RIPEAtlasMonitorError.__init__(self)
        self.path = path

    def __str__(self):
        return "The file {} does not exist".format(self.path)


class ConfigError(RIPEAtlasMonitorError):
    pass


class GlobalConfigError(RIPEAtlasMonitorError):

    def __str__(self):
        return "Global configuration error: {}".format(self.args[0])


class ArgumentError(RIPEAtlasMonitorError):
    pass


class MeasurementProcessingError(RIPEAtlasMonitorError):
    pass


class ResultProcessingError(RIPEAtlasMonitorError):
    pass


class LockError(RIPEAtlasMonitorError):
    pass


class ProgramError(RIPEAtlasMonitorError):
    """
    Use this to catch unhandled exception and keep track of the
    exc_info and traceback information.
    """

    def __init__(self, *args, **kwargs):
        RIPEAtlasMonitorError.__init__(self, *args, **kwargs)
        self.err_descr = format_exc()

    def __str__(self):
        if self.err_descr:
            indent = "    "
            s = indent + ("\n"+indent).join(self.err_descr.split("\n"))

            return "{}\n{}".format(self.args[0], s)
        else:
            return self.args[0]
