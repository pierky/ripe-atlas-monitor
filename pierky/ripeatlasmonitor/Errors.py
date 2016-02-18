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
