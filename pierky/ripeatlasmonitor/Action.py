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

from email.mime.text import MIMEText
import logging
from os import environ
from smtplib import SMTP, SMTP_SSL, SMTPException
import socket
from subprocess import call

from .Config import Config
from .emailsettings import read_email_settings
from .Errors import ConfigError, ProgramError
from .Helpers import BasicConfigElement
from .Logging import logger, CustomSysLogLogger


class Action(BasicConfigElement):
    """Action

    Action performed on the basis of expected results processing for probes
    which match the `matching_rules` rules.

    `kind`: type of action.

    `descr` (optional): brief description of the action.

    `when` (optional): when the action must be performed (with regards of
    expected results processing output); one of "on_match", "on_mismatch",
    "always". Default: "on_mismatch".

    When a probe matches a rule, it's expected results are processed; on the
    basis of the output, actions given in the rule's `actions` list are
    performed.
    For each expected result, if the probe's collected result matches the
    expectation actions whose `when` = "on_match" or "always" are performed.
    If the collected result does not match the expected result, actions
    whose `when` = "on_mismatch" or "always" are performed.
    """

    CFG_ACTION_KIND = None
    MANDATORY_CFG_FIELDS = ["kind"]
    OPTIONAL_CFG_FIELDS = ["descr", "when"]

    @classmethod
    def get_cfg_fields(cls):
        m = set(Action.MANDATORY_CFG_FIELDS)
        o = set(Action.OPTIONAL_CFG_FIELDS)

        if cls != Action:
            m.update(set(cls.MANDATORY_CFG_FIELDS))
            o.update(set(cls.OPTIONAL_CFG_FIELDS))

        return m, o

    def __init__(self, monitor, name, cfg):
        BasicConfigElement.__init__(self, cfg)

        self.monitor = monitor

        self.normalize_fields()

        self.name = name

        self.descr = cfg["descr"]

        self.kind = self._enforce_param("kind", str)

        if not self.kind:
            raise ConfigError("Missing action kind.")

        if self.kind != self.CFG_ACTION_KIND:
            raise ConfigError(
                "Wrong action kind: {} expected, {} found.".format(
                    self.CFG_ACTION_KIND, self.kind
                )
            )

        self.when = self._enforce_param("when", str) or "on_mismatch"

        WHEN = ("on_match", "on_mismatch", "always")

        if self.when not in WHEN:
            raise ConfigError(
                "Unexpected when ({}): must be one of {}".format(
                    self.when, ", ".join(WHEN)
                )
            )

    def __str__(self):
        raise NotImplementedError()

    def perform(self, result, expres, result_matches):
        raise NotImplementedError()

    def ping_output(self, result):
        # Stolen from https://github.com/RIPE-NCC/ripe-atlas-tools
        # (/blob/master/ripe/atlas/tools/renderers/ping.py)

        packets = result.packets

        if not packets:
            return "No packets found"

        # Because the origin value is more reliable as "from" in v4 and as
        # "packet.source_address" in v6.
        origin = result.origin
        if ":" in origin:
            origin = packets[0].source_address

        line = "{} bytes from probe #{:<5} {:15} to {} ({}): ttl={} times:{}\n"
        return line.format(
            result.packet_size,
            result.probe_id,
            origin,
            result.destination_name,
            result.destination_address,
            packets[0].ttl,
            " ".join(["{:8}".format(str(_.rtt) + ",") for _ in packets])
        )

    def traceroute_output(self, result):
        # Based on https://github.com/RIPE-NCC/ripe-atlas-tools

        r = ""
        for hop in result.hops:
            if hop.is_error:
                r += "{}\n".format(hop.error_message)
                continue

            name = ""
            rtts = []
            ip_info = None
            asn = ""
            details = ""
            for packet in hop.packets:
                if packet.origin and packet.origin != "*":
                    if not ip_info:
                        ip_info = self.monitor.ip_cache.get_ip_info(
                            packet.origin
                        )

                        asn = ip_info["ASN"]
                        ixp = ip_info["IsIXP"]
                        ixp_name = ip_info["IXPName"]

                        if asn and asn.isdigit():
                            details = "AS{}".format(asn)
                        elif ixp:
                            details = "IX {}".format(ixp_name)
                        else:
                            details = ""

                name = name or packet.origin or "*"
                if packet.rtt:
                    rtts.append("{:8} ms".format(packet.rtt))
                else:
                    rtts.append("          *")

            r += "{:>3} {:39} {}\n".format(
                hop.index,
                "{} {}".format(name, details),
                "  ".join(rtts)
            )
        return r

    def sslcert_output(self, result):
        r = ""

        TPL = ("SHA256 Fingerprint={sha256fp}\n"
               "  Issuer: C={issuer_c}, O={issuer_o}, CN={issuer_cn}\n"
               "  Subject: C={subject_c}, O={subject_o}, CN={subject_cn}\n")

        for certificate in result.certificates:
            r += TPL.format(
                issuer_c=certificate.issuer_c,
                issuer_o=certificate.issuer_o,
                issuer_cn=certificate.issuer_cn,
                subject_c=certificate.subject_c,
                subject_o=certificate.subject_o,
                subject_cn=certificate.subject_cn,
                sha256fp=certificate.checksum_sha256
            )

        return r

    def dns_output(self, result):
        r = ""

        if not result.responses:
            return "No response found"

        response_idx = 0
        indent = ""

        for response in result.responses:
            response_idx += 1

            if response_idx > 1:
                r += "\n"

            if len(result.responses) > 1:
                r += "Response n. {}\n\n".format(response_idx)
                indent = "  "

            if not response.abuf:
                r += indent + "Can't parse response's abuf\n"
                continue

            r += indent + "Header: {}, {}, id: {}\n".format(
                response.abuf.header.opcode,
                response.abuf.header.return_code,
                response.abuf.header.id
            )

            header_flags = []
            for flag in ("aa", "ad", "cd", "qr", "ra", "rd",):
                if getattr(response.abuf.header, flag):
                    header_flags.append(flag)

            r += indent + "Header flags: {}\n".format(", ".join(header_flags))

            if response.abuf.edns0:
                r += indent + "EDNS: version {}, size {}{}\n".format(
                        response.abuf.edns0.version,
                        response.abuf.edns0.udp_size,
                        ", DO flag" if response.abuf.edns0.do else ""
                    )

            for section in ("answers", "authorities", "additionals"):
                r += indent + "Section: {}\n".format(section)

                section = getattr(response.abuf, section)

                if len(section) > 0:
                    for record in section:
                        r += indent + "  " + str(record) + "\n"
                else:
                    r += indent + "  " + "no records\n"

        return r

    def get_result_text(self, result, expres):
        if self.monitor.msm_type == "traceroute":
            return self.traceroute_output(result)
        elif self.monitor.msm_type == "ping":
            return self.ping_output(result)
        elif self.monitor.msm_type == "sslcert":
            return self.sslcert_output(result)
        elif self.monitor.msm_type == "dns":
            return self.dns_output(result)
        else:
            raise NotImplementedError(
                "Action non implemented for {} "
                "measurements.".format(self.monitor.msm_type)
            )

    def get_notification_text(self, result, expres):

        probe = self.monitor.get_probe(result)

        r = ("{monitor}\n\n"
             "Received result from {probe} at {time}\n\n"
             "Expected result: {expres}\n\n"
             "{result}").format(
                monitor=self._capitalize_first(str(self.monitor)),
                expres=str(expres) if expres else "none",
                probe=str(probe),
                time=str(result.created),
                result=self.get_result_text(result, expres)
            )

        return r


class ActionLog(Action):
    """Action log

    Log the match/mismatch along with the collected result.

    No parameters required.
    """

    CFG_ACTION_KIND = "log"
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    def __init__(self, monitor, name, cfg):
        Action.__init__(self, monitor, name, cfg)

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            return "Log the received result"

    def perform(self, result, expres, result_matches):
        r = self.get_notification_text(result, expres)

        logger.action_log(r)


class ActionSysLog(Action):
    """Action syslog

    Log the match/mismatch along with the collected result using syslog.

    `socket` (optional): where the syslog message has to be logged. One of
    "file", "udp", "tcp".

    `host` (optional): meaningful only when `socket` is "udp" or "tcp". Host
    where send the syslog message to.

    `port` (optional): meaningful only when `socket` is "udp" or "tcp".
    UDP/TCP port where send the syslog message to.

    `file` (optional): meaningful only when `socket` is "file". File where the
    syslog message has to be written to.

    `facility` (optional): syslog facility that must be used to log the
    message.

    `priority` (optional): syslog priority that must be used to log the
    message.

    Parameters which are not given are read from the global configuration
    file `default_syslog` section.
    """

    CFG_ACTION_KIND = "syslog"
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = ["socket", "host", "port", "file", "facility",
                           "priority"]

    @staticmethod
    def _get_level(name):
        if name == "alert":
            return logging.CRITICAL
        elif name in ["crit", "critical"]:
            return logging.CRITICAL
        elif name == "debug":
            return logging.DEBUG
        elif name in ["emerg", "panic"]:
            return logging.CRITICAL
        elif name in ["err", "error"]:
            return logging.ERROR
        elif name == "info":
            return logging.INFO
        elif name == "notice":
            return logging.INFO
        elif name in ["warn", "warning"]:
            return logging.WARNING
        else:
            return None

    def __init__(self, monitor, name, cfg):
        Action.__init__(self, monitor, name, cfg)

        self.socket = self._enforce_param("socket", str) or \
            Config.get("default_syslog.socket")
        if not self.socket:
            raise ConfigError("Missing socket.")
        elif self.socket not in ["udp", "tcp", "file"]:
            raise ConfigError(
                "Invalid socket type: {}. It must be one "
                "of 'udp', 'tcp' or 'file'.".format(self.socket)
            )

        self.host = None
        self.port = None
        self.file = None

        if self.socket in ["udp", "tcp"]:
            self.host = self._enforce_param("host", str) or \
                Config.get("default_syslog.host")
            if not self.host:
                raise ConfigError(
                    "Missing host. It's mandatory when socket "
                    "is 'tcp' or 'udp'."
                )

            self.port = self._enforce_param("port", int) or \
                Config.get("default_syslog.port")
            if not self.port:
                raise ConfigError(
                    "Missing port. It's mandatory when socket "
                    "is 'tcp' or 'udp'."
                )
        else:
            self.file = self._enforce_param("file", str) or \
                Config.get("default_syslog.file")
            if not self.file:
                raise ConfigError(
                    "Missing file. It's mandatory when socket "
                    "is 'file'."
                )

        self.facility = self._enforce_param("facility", str) or \
            Config.get("default_syslog.facility")
        if not self.facility:
            raise ConfigError("Missing facility.")
        if self.facility not in ["auth", "authpriv", "cron", "daemon", "ftp",
                                 "kern", "lpr", "mail", "news", "syslog",
                                 "user", "uucp", "local0", "local1", "local2",
                                 "local3", "local4", "local5", "local6",
                                 "local7"]:
            raise ConfigError("Invalid facility: {}".format(self.facility))

        self.priority = self._enforce_param("priority", str) or \
            Config.get("default_syslog.priority")
        if not self.priority:
            raise ConfigError("Missing priority.")
        self.log_level = self._get_level(self.priority)
        if not self.log_level:
            raise ConfigError(
                "Invalid priority: {}. Must be one of "
                "'alert', 'crit', 'critical', 'debug', 'emerg', 'panic', "
                "'err', 'error', 'info', 'notice', 'warn', "
                "'warning'.".format(self.priority)
            )

        self.logger_name = "{socket}-{address}-{facility}-{priority}".format(
            socket=self.socket,
            address=self.file if self.socket == "file" else "{}:{}".format(
                self.host, self.port
            ),
            facility=self.facility,
            priority=self.priority
        )

        self.logger = None
        self.logger_ready = False

    def _setup_logger(self):
        if self.logger:
            return self.logger_ready

        self.logger = CustomSysLogLogger(self.logger_name)

        try:
            self.logger.setup(
                self.socket,
                self.file if self.socket == "file" else (self.host, self.port),
                self.facility
            )
        except Exception:
            logger.error(
                "Error while setting up the syslog logger "
                "for action {}".format(str(self)),
                exc_info=True
            )

        self.logger_ready = True
        return True

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            return "Send a syslog message to {}".format(
                self.file if self.file else "{}:{}:{}".format(
                    self.socket, self.host, self.port
                )
            )

    def perform(self, result, expres, result_matches):
        if not self._setup_logger():
            return

        probe = self.monitor.get_probe(result)

        if result_matches is None:
            status = "Received"
        else:
            status = "Expected" if result_matches else "Unexpected"

        msg = "{monitor} - {status} result from {probe} at {time}".format(
            status=status,
            monitor=self._capitalize_first(str(self.monitor)),
            probe=str(probe),
            time=str(result.created),
        )

        self.logger.log(self.log_level, msg)


class ActionSendEMail(Action):
    """Action email

    Send an email with the expected result processing output.

    `from_addr` (optional): email address used in the From field.

    `to_addr` (optional): email address used in the To field.

    `subject` (optional): subject of the email message.

    `smtp_host` (optional): SMTP server's host.

    `smtp_port` (optional): SMTP server's port.

    `use_ssl` (optional): boolean indicating whether the connection
    toward SMTP server must use encryption.

    `username` (optional): username for SMTP authentication.

    `password` (optional): password for SMTP authentication.

    `timeout` (optional): timeout, in seconds.

    Parameters which are not given are read from the global configuration
    file `default_smtp` section.
    """

    CFG_ACTION_KIND = "email"
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = ["from_addr", "to_addr", "subject", "smtp_host",
                           "smtp_port", "use_ssl", "username", "password",
                           "timeout"]

    def __init__(self, monitor, name, cfg):
        Action.__init__(self, monitor, name, cfg)

        email_settings = read_email_settings(
            from_addr=self._enforce_param("from_addr", str),
            to_addr=self._enforce_list("to_addr", str),
            subject=self._enforce_param("subject", str),
            smtp_host=self._enforce_param("smtp_host", str),
            smtp_port=self._enforce_param("smtp_port", int),
            timeout=self._enforce_param("timeout", int),
            use_ssl=self._enforce_param("use_ssl", bool),
            username=self._enforce_param("username", str),
            password=self._enforce_param("password", str)
        )

        for _ in email_settings:
            setattr(self, _, email_settings[_])

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            return "Send an email to {}".format(", ".join(self.to_addr))

    def perform(self, result, expres, result_matches):
        r = self.get_notification_text(result, expres)

        probe = self.monitor.get_probe(result)

        if result_matches is None:
            status = "has been received"
        elif result_matches:
            status = "matched expected values"
        else:
            status = "did not match expected values"

        body = ("A result from {monitor} {status}.\n\n"
                "{probe} - expected result {expres}\n\n"
                "-------------------------------------\n\n{res}").format(
                    monitor=str(self.monitor), status=status,
                    probe=str(probe), expres=str(expres) if expres else "none",
                    res=r)

        if self.use_ssl:
            smtp_class = SMTP_SSL
        else:
            smtp_class = SMTP

        msg = MIMEText(body)
        msg["Subject"] = self.subject
        msg["From"] = self.from_addr
        msg["To"] = ",".join(self.to_addr)

        try:
            smtp = smtp_class(host=self.smtp_host, port=self.smtp_port,
                              timeout=self.timeout)

            if self.username:
                smtp.login(self.username, self.password)

            if hasattr(smtp, "send_message"):
                smtp.send_message(msg, self.from_addr, self.to_addr)
            else:
                smtp.sendmail(self.from_addr, self.to_addr, msg.as_string())
            smtp.quit()
        except (SMTPException, socket.error, socket.herror, socket.gaierror,
                socket.timeout):
            raise ProgramError(
                "Error while sending email to {} via {}:{}".format(
                    ", ".join(self.to_addr), self.smtp_host, self.smtp_port
                )
            )


class ActionRunProgram(Action):
    """Action run

    Run an external program.

    `path`: path of the program to run.

    `env_prefix` (optional): prefix used to build environment variables.

    `args` (optional): list of arguments which have to be passed to the
    program. If the argument starts with "$" it is replaced with the
    value of the variable with the same name.

    If `env_prefix` is not given, it's value is taken from the global
    configuration file `misc.env_prefix` parameter.

    Variables are:

    - `ResultMatches`: True, False or None
    - `MsmID`: measurement's ID
    - `MsmType`: measurement's type (ping, traceroute, sslcert, dns)
    - `MsmAF`: measurement's address family (4, 6)
    - `MsmStatus`: measurement's status (Running, Stopped)
      [https://atlas.ripe.net/docs/rest/]
    - `MsmStatusID`: measurement's status ID
      [https://atlas.ripe.net/docs/rest/]
    - `Stream`: True or False
    - `ProbeID`: probe's ID
    - `ProbeCC`: probe's ISO Country Code
    - `ProbeASNv4`: probe's ASN (IPv4)
    - `ProbeASNv6`: probe's ASN (IPv6)
    - `ProbeASN`: probe's ASN related to measurement's address family
    - `ResultCreated`: timestamp of result's creation date/time

    Example:

    actions:
      RunMyProgram:
        kind: run
        path: /path/to/my-program
        args:
        - command
        - -o
        - --msm
        - $MsmID
        - --probe
        - $ProbeID
    """

    CFG_ACTION_KIND = "run"
    MANDATORY_CFG_FIELDS = ["path"]
    OPTIONAL_CFG_FIELDS = ["env_prefix", "args"]

    VARIABLES = (
        "ResultMatches",
        "MsmID",
        "MsmType",
        "MsmAF",
        "MsmStatus",
        "MsmStatusID",
        "Stream",
        "ProbeID",
        "ProbeCC",
        "ProbeASNv4",
        "ProbeASNv6",
        "ProbeASN",
        "ResultCreated"
    )

    def __init__(self, monitor, name, cfg):
        Action.__init__(self, monitor, name, cfg)

        self.path = self._enforce_param("path", str)

        self.env_prefix = self._enforce_param("env_prefix", str) or \
            Config.get("misc.env_prefix")

        self.args = self._enforce_list("args", str) or []

        self.get_args()

    def get_args(self, env_base=None):
        args = []
        for arg in self.args:
            if arg.startswith("$"):
                arg = arg[1:]
                if arg not in self.VARIABLES:
                    raise ConfigError(
                        "Invalid variable: ${}. It must be one "
                        "of ${}.".format(arg,
                                         ", $".join(self.VARIABLES))
                    )
                else:
                    if env_base:
                        arg = str(env_base[arg])
                    else:
                        arg = "$" + arg
            args.append(arg)
        return args

    def _get_full_path(self):
        args = [self.path]
        args += self.get_args()
        return " ".join(args)

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            return "Run external program {}".format(
                self._get_full_path()
            )

    def perform(self, result, expres, result_matches):
        probe = self.monitor.get_probe(result)

        env_base = {
            "ResultMatches": result_matches,
            "MsmID": self.monitor.msm_id,
            "MsmType": self.monitor.msm_type,
            "MsmAF": self.monitor.msm_af,
            "MsmStatus": self.monitor.msm_status,
            "MsmStatusID": self.monitor.msm_status_id,
            "Stream": self.monitor.stream,
            "ProbeID": probe.id,
            "ProbeCC": probe.country_code,
            "ProbeASNv4": probe.asn_v4,
            "ProbeASNv6": probe.asn_v6,
            "ProbeASN": probe.asn,
            "ResultCreated": result.created
        }

        # verify all the env_base variables are known
        if set(env_base.keys()) != set(self.VARIABLES):
            raise ProgramError(
                "Error in ActionRunProgram class: variables mismatch"
            )

        env = environ
        for k in env_base:
            env["{}{}".format(self.env_prefix, k)] = str(env_base[k])

        args = [self.path] + self.get_args(env_base)

        try:
            call(args, env=env)
        except:
            raise ProgramError(
                "Error while running external program {}".format(
                    self._get_full_path()
                )
            )


class ActionLabel(Action):
    """Action label

    Add or remove custom labels to/from probes.

    `op`: operation; one of "add" or "del".

    `label_name`: label to be added/removed.

    `scope` (optional): scope of the label; one of "result" or "probe".
    Default: "result".

    Labels can be added to probes and subsequently used to match those probes
    in other rules (`internal_labels` criterion).

    If scope is "result", the operation is significative only within the
    current result processing (that is, within the current `matching_rules`
    processing for the current result). Labels added to probe are
    removed when the current result processing is completed.

    If scope is "probe", the operation is persistent across results processing.
    """

    CFG_ACTION_KIND = "label"
    MANDATORY_CFG_FIELDS = ["op", "label_name"]
    OPTIONAL_CFG_FIELDS = ["scope"]

    def __init__(self, monitor, name, cfg):
        Action.__init__(self, monitor, name, cfg)

        self.op = self._enforce_param("op", str)

        TAG_OPS = ["add", "del"]
        if self.op not in TAG_OPS:
            raise ConfigError(
                "Invalid label operation: {}. Must be one of {}".format(
                    self.op, ", ".join(TAG_OPS)
                )
            )

        self.label_name = self._enforce_param("label_name", str)

        self.scope = self._enforce_param("scope", str) or "result"

        TAG_SCOPES = ["probe", "result"]
        if self.scope and self.scope not in TAG_SCOPES:
            raise ConfigError(
                "Invalid label scope: {}. Must be one of {}".format(
                    self.scope, ", ".join(TAG_SCOPES)
                )
            )

    def __str__(self):
        if self.descr:
            return self.descr
        else:
            if self.op == "add":
                return "Add label {} to {}".format(
                    self.label_name, self.scope
                )
            elif self.op == "del":
                return "Remove label {} from {}".format(
                    self.label_name, self.scope
                )
            else:
                raise NotImplementedError()

    def perform(self, result, expres, result_matches):
        probe = self.monitor.get_probe(result)

        lbl_key = str(probe.id)
        if self.scope == "probe":
            labels = self.monitor.internal_labels["probes"]
        elif self.scope == "result":
            labels = self.monitor.internal_labels["results"]
        else:
            raise NotImplementedError()

        if self.op == "add":
            if lbl_key not in labels:
                labels[lbl_key] = set()

            tpl = "adding label {name} to {scope} {key}"
            labels[lbl_key].add(self.label_name)

        elif self.op == "del":
            if lbl_key in labels and self.label_name in labels[lbl_key]:

                tpl = "removing label {name} from {scope} {key}"
                labels[lbl_key].remove(self.label_name)
            else:
                tpl = "label {name} already missing from {scope} {key}"

        else:
            raise NotImplementedError()

        logger.debug(
            tpl.format(
                name=self.label_name,
                scope=self.scope,
                key=lbl_key
            )
        )


ACTION_CLASSES = [
    ActionLog,
    ActionSendEMail,
    ActionRunProgram,
    ActionSysLog,
    ActionLabel
]
