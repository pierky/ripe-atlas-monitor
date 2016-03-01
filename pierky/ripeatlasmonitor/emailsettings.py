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

import re

from .Errors import ConfigError
from .Config import Config


EMAIL_ADDR_VALIDATION_RE = re.compile(
    Config.get("misc.email_addr_re"),
    flags=re.IGNORECASE
)


def is_valid_email(s):
    return EMAIL_ADDR_VALIDATION_RE.match(s)


def read_email_settings(**kwargs):

    from_addr = kwargs.get("from_addr") or \
        Config.get("default_smtp.from_addr")
    if from_addr:
        if not is_valid_email(from_addr):
            raise ConfigError(
                "Invalid email address in {}: {}".format(
                    "from_addr", from_addr
                )
            )

    to_addr = kwargs.get("to_addr") or \
        Config.get("default_smtp.to_addr")
    if to_addr:
        if isinstance(to_addr, list):
            addresses = to_addr
        else:
            addresses = [to_addr]

        for addr in addresses:
            if not is_valid_email(addr):
                raise ConfigError(
                    "Invalid email address in {}: {}".format(
                        "to_addr", addr
                    )
                )
        to_addr = addresses

    subject = kwargs.get("subject") or \
        Config.get("default_smtp.subject")

    smtp_host = kwargs.get("smtp_host") or \
        Config.get("default_smtp.smtp_host")

    smtp_port = kwargs.get("smtp_port") or \
        Config.get("default_smtp.smtp_port")

    timeout = kwargs.get("timeout") or \
        Config.get("default_smtp.timeout")

    use_ssl = kwargs.get("use_ssl")
    if use_ssl is None:
        use_ssl = Config.get("default_smtp.use_ssl")

    username = kwargs.get("username") or \
        Config.get("default_smtp.username")

    password = kwargs.get("password") or \
        Config.get("default_smtp.password")

    if smtp_host is None:
        raise ConfigError("Missing SMTP server host")
    if smtp_port is None:
        raise ConfigError("Missing SMTP server port")
    if subject is None:
        raise ConfigError("Missing subject")
    if from_addr is None:
        raise ConfigError("Missing from address")
    if to_addr is None or len(to_addr) == 0:
        raise ConfigError("Missing recipient address(es)")

    return {
        "from_addr": from_addr,
        "to_addr": to_addr,
        "subject": subject,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "timeout": timeout,
        "use_ssl": use_ssl,
        "username": username,
        "password": password
    }
