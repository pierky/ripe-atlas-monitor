import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
from socket import SOCK_DGRAM, SOCK_STREAM
import sys


from Config import Config


LOG_LVL_RESULT = 25
LOG_LVL_LOG_ACTION = 27


class CustomLogger(object):
    def __init__(self):
        self.lvl = 0

        self.logger = logging.getLogger("RIPEAtlasMonitor")

        logging.addLevelName(LOG_LVL_RESULT, "RESULT")
        logging.addLevelName(LOG_LVL_LOG_ACTION, "LOG-ACTION")

        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)

        self.stream_hdlr = logging.StreamHandler(stream=sys.stdout)
        fmt = logging.Formatter("[%(processName)s] %(message)s")
        self.stream_hdlr.setFormatter(fmt)
        self.stream_hdlr.setLevel(logging.WARNING)
        self.logger.addHandler(self.stream_hdlr)

    def setup(self, verbosity_lvl):
        self.lvl = verbosity_lvl

        if self.lvl == 0:
            logging_level = logging.WARNING
        elif self.lvl == 1:
            logging_level = LOG_LVL_LOG_ACTION
        elif self.lvl == 2:
            logging_level = LOG_LVL_RESULT
        elif self.lvl == 3:
            logging_level = logging.INFO
        elif self.lvl >= 4:
            logging_level = logging.DEBUG

        self.stream_hdlr.setLevel(logging_level)

        file_path = Config.get("logging.file_path")
        if file_path:
            hdlr = RotatingFileHandler(
                file_path,
                maxBytes=Config.get("logging.max_bytes"),
                backupCount=Config.get("logging.backup_cnt")
            )
            fmt = logging.Formatter(
                "%(asctime)s [%(processName)s] %(levelname)s %(message)s"
            )
            hdlr.setFormatter(fmt)
            if logging_level < LOG_LVL_LOG_ACTION:
                hdlr.setLevel(logging_level)
            else:
                hdlr.setLevel(LOG_LVL_LOG_ACTION)
            self.logger.addHandler(hdlr)

    def log(self, lvl, msg, exc_info=False):
        self.logger.log(lvl, msg, exc_info=exc_info)

    def error(self, msg, exc_info=False):
        self.log(logging.ERROR, msg, exc_info=exc_info)

    def warning(self, msg):
        self.log(logging.WARNING, msg)

    def info(self, msg):
        self.log(logging.INFO, msg)

    def debug(self, msg):
        self.log(logging.DEBUG, msg)

    def result(self, msg):
        self.log(LOG_LVL_RESULT, msg)

    def action_log(self, msg):
        self.log(LOG_LVL_LOG_ACTION, msg)


class CustomSysLogLogger(object):

    def __init__(self, name):
        self.name = name
        self.logger = logging.getLogger(
            "RIPEAtlasMonitorSysLog-{}".format(name)
        )
        self.logger.setLevel(1)

    def setup(self, socket, address, facility):
        if socket == "file":
            socktype = None
        elif socket == "udp":
            socktype = SOCK_DGRAM
        elif socket == "tcp":
            socktype = SOCK_STREAM

        hdlr = SysLogHandler(
            address=address,
            facility=facility,
            socktype=socktype
        )
        hdlr.setLevel(1)

        fmt = logging.Formatter(
            "RIPEAtlasMonitor[%(process)d] %(message)s"
        )

        hdlr.setFormatter(fmt)

        self.logger.addHandler(hdlr)

    def log(self, lvl, msg, *args, **kwargs):
        self.logger.log(lvl, msg, *args, **kwargs)

logger = CustomLogger()
