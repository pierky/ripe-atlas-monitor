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

import copy
import os
import sys
import yaml


from .Errors import MissingFileError, GlobalConfigError

DEFAULT_CFG_PATH = "/etc/ripe-atlas-monitor/config.cfg"


class GlobalConfig(object):

    DEFAULT_CFG = {
        "var_dir": "",
        "verbosity": 0,
        "logging": {
            "file_path": "",
            "max_bytes": 10000000,
            "backup_cnt": 3,
            "email": {
                "to_addr": "",

                # on parse, if one of the following parameters is null
                # it's set with the same taken from default_smtp
                "smtp_host": str,
                "smtp_port": int,
                "from_addr": str,
                "subject": str,
                "use_ssl": bool,
                "username": str,
                "password": str,
                "timeout": int
            }
        },
        "ip_cache": {
            "dir": "",  # on load, it will be set to var_dir if missing
            "use_ixps_info": True,
            "lifetime": 604800
        },
        "default_smtp": {
            "smtp_host": "",
            "smtp_port": 25,
            "from_addr": "",
            "to_addr": "",
            "subject": "",
            "use_ssl": False,
            "username": "",
            "password": "",
            "timeout": 60
        },
        "default_syslog": {
            "socket": "",
            "host": "",
            "port": 514,
            "file": "",
            "facility": "user",
            "priority": "warning"
        },
        "misc": {
            "email_addr_re": "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$",
            "env_prefix": "RIPE_ATLAS_MONITOR_",
            "msm_results_days_limit": 7,
            "editor": "/usr/bin/vim"
        }
    }

    def __init__(self):
        self.cfg = copy.deepcopy(GlobalConfig.DEFAULT_CFG)
        self.cfg_path = None

        curr_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

        self.cfg["var_dir"] = "{}/var".format(curr_dir)
        self.cfg["ip_cache"]["dir"] = "{}/var".format(curr_dir)

    @staticmethod
    def _test_dir(dir_path, config_param):
        if not os.path.isdir(dir_path):
            raise GlobalConfigError(
                "the directory referenced by {} ({}) "
                "does not exist".format(config_param, dir_path)
            )

        try:
            tmp = "{}/wr_test.tmp".format(dir_path)
            with open(tmp, "w") as f:
                f.write("test")
            os.remove(tmp)
        except Exception as e:
            raise GlobalConfigError(
                "can't write files into {} ({}): {}. "
                "Please check permissions".format(
                    config_param, dir_path, str(e)
                )
            )

    def get_default_path(self):
        if "HOME" in os.environ:
            return os.path.join(
                os.environ["HOME"], ".config", "ripe-atlas-monitor")
        else:
            return DEFAULT_CFG_PATH

    def init_file(self, path):
        tpl_file = os.path.join(
            os.path.dirname(__file__), "templates", "global_config.yaml"
        )

        try:
            with open(tpl_file, "r") as tpl:
                cfg = tpl.read()
        except Exception as e:
            raise GlobalConfigError(
                "Error while reading global config template "
                "file {}: {}".format(tpl_file, e)
            )
        try:
            with open(path, "w") as dest:
                dest.write(cfg)
        except Exception as e:
            raise GlobalConfigError(
                "Error writing global config template to "
                "{}: {}".format(path, e)
            )

    def load(self, cfg_path=DEFAULT_CFG_PATH):
        self.cfg = copy.deepcopy(GlobalConfig.DEFAULT_CFG)
        self.cfg_path = cfg_path

        if not os.path.isfile(self.cfg_path):
            raise MissingFileError(self.cfg_path)

        with open(self.cfg_path, "r") as f:
            try:
                custom = yaml.load(f.read())
            except Exception as e:
                raise GlobalConfigError(
                    "can't parse YAML file: {}".format(str(e))
                )
            self.parse(custom)

    def verify_dirs(self):
        var_dir = self.get("var_dir")

        if not var_dir:
            raise GlobalConfigError("mandatory option missing: var_dir")

        self._test_dir(var_dir, "var_dir")

        for d in ["status", "locks", "monitors"]:
            full_path = "{}/{}".format(var_dir, d)
            if not os.path.isdir(full_path):
                try:
                    os.makedirs(full_path)
                except Exception as e:
                    raise GlobalConfigError(
                        "can't create the {} directory inside var_dir ({}): "
                        "{}. Please check permissions".format(
                            d, var_dir, str(e)
                        )
                    )

        if not self.get("ip_cache.dir"):
            self.cfg["ip_cache"]["dir"] = var_dir

        ip_cache_dir = self.cfg["ip_cache"]["dir"]

        self._test_dir(ip_cache_dir, "ip_cache.dir")

    def parse(self, custom):
        if custom:
            self.merge(self.cfg, custom)

            for p in ["smtp_host", "smtp_port", "from_addr", "subject",
                      "use_ssl", "username", "password", "timeout"]:
                if self.cfg["logging"]["email"][p] is None or \
                        isinstance(self.cfg["logging"]["email"][p], type):
                    self.cfg["logging"]["email"][p] = \
                        self.get("default_smtp.{}".format(p))

    def merge(self, orig, new):
        for k, v in new.items():
            if k not in orig:
                raise GlobalConfigError(
                    "unknown parameter ({})".format(k)
                )

            if v is None:
                continue

            if isinstance(v, dict):
                self.merge(orig[k], v)
            else:
                if isinstance(v, type(orig[k])):
                    orig[k] = v
                elif isinstance(orig[k], type) and isinstance(v, orig[k]):
                    orig[k] = v
                else:
                    raise GlobalConfigError(
                        "invalid type for {}. "
                        "It is {} but it must be {}.".format(
                            k, type(v), type(orig[k])
                        )
                    )

    def _get(self, cfg, param):
        if len(param) == 1:
            return cfg[param[0]]
        else:
            return self._get(cfg[param[0]], param[1:])

    def get(self, param):
        r = self._get(self.cfg, param.split("."))
        if isinstance(r, str) and r.strip() == "":
            return None
        elif isinstance(r, list) and len(r) == 0:
            return None
        return r

Config = GlobalConfig()
