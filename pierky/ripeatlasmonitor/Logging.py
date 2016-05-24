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

import logging
from logging.handlers import RotatingFileHandler, SysLogHandler, SMTPHandler
from socket import SOCK_DGRAM, SOCK_STREAM
import six
import sys


from .Config import Config
from .emailsettings import read_email_settings
from .Errors import ConfigError


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

        self.setup_done = False

    def setup(self, verbosity_lvl, stdout=True):
        self.setup_done = True

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

        if stdout:
            stream_hdlr = logging.StreamHandler(stream=sys.stdout)
            fmt = logging.Formatter("[%(processName)s] %(message)s")
            stream_hdlr.setFormatter(fmt)
            stream_hdlr.setLevel(logging_level)
            self.logger.addHandler(stream_hdlr)

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

        to_addr = Config.get("logging.email.to_addr")
        if to_addr:
            try:
                email_settings = read_email_settings(
                    from_addr=Config.get("logging.email.from_addr"),
                    to_addr=Config.get("logging.email.to_addr"),
                    subject=Config.get("logging.email.subject"),
                    smtp_host=Config.get("logging.email.smtp_host"),
                    smtp_port=Config.get("logging.email.smtp_port"),
                    timeout=Config.get("logging.email.timeout"),
                    use_ssl=Config.get("logging.email.use_ssl"),
                    username=Config.get("logging.email.username"),
                    password=Config.get("logging.email.password")
                )
            except ConfigError as e:
                raise ConfigError(
                    "Error setting up the email error logging system: {}. "
                    "Please review the 'logging.email.*' global config "
                    "options or disable email error logging by removing the "
                    "'logging.email.to_addr' option.".format(
                        str(e)
                    )
                )

            args = {
                "mailhost": (email_settings["smtp_host"],
                             email_settings["smtp_port"]),
                "fromaddr": email_settings["from_addr"],
                "toaddrs": email_settings["to_addr"],
                "subject": email_settings["subject"],
                "credentials": (email_settings["username"],
                                email_settings["password"]),
                "secure": () if email_settings["use_ssl"] else None,
            }
            if six.PY3:
                args["timeout"] = email_settings["timeout"]

            hdlr = SMTPHandler(**args)
            fmt = logging.Formatter(
                "%(asctime)s [%(processName)s] %(levelname)s %(message)s"
            )
            hdlr.setFormatter(fmt)
            hdlr.setLevel(logging.ERROR)
            self.logger.addHandler(hdlr)

    def log(self, lvl, msg, exc_info=False):
        if self.setup_done:
            self.logger.log(lvl, msg, exc_info=exc_info)
        else:
            if lvl >= logging.ERROR:
                sys.stderr.write(
                    "RIPEAtlasMonitor: lvl {}, {}\n".format(lvl, msg)
                )

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
