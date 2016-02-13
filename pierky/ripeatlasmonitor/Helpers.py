import errno
import fcntl
import os
from multiprocessing.managers import BaseManager

from Errors import ConfigError, ProgramError
from Logging import logger
from pierky.ipdetailscache import IPDetailsCache, \
                                  IPDetailsCacheIXPInformationError


class BasicConfigElement(object):
    MANDATORY_CFG_FIELDS = []
    OPTIONAL_CFG_FIELDS = []

    @classmethod
    def get_cfg_fields(cls):
        m = set(cls.MANDATORY_CFG_FIELDS)
        o = set(cls.OPTIONAL_CFG_FIELDS)

        return m, o

    def __init__(self, cfg):
        self.cfg = cfg

    @classmethod
    def get_all_cfg_fields(cls):
        m, o = cls.get_cfg_fields()
        return m.union(o)

    def _enforce_type(self, v, t):
        if v is None:
            return None
        else:
            if type(v) != t:
                if type(v) == str and t == int:
                    if v.isdigit():
                        return int(v)
                elif type(v) == str and t == bool:
                    if v.lower() in ["y", "yes", "t", "true", "on", "1"]:
                        return True
                    elif v.lower() in ["n", "no", "f", "false", "off", "0"]:
                        return False

                raise ConfigError(
                    "Invalid type for '{}': "
                    "must be {}".format(v, t)
                )
            else:
                return v

    def _enforce_param(self, k, t):
        if k not in self.get_all_cfg_fields():
            raise AttributeError("Unknown attribute: {}".format(k))
        if k not in self.cfg:
            return None
        else:
            if isinstance(self.cfg[k], str) and self.cfg[k].strip() == "":
                return None
            else:
                return self._enforce_type(self.cfg[k], t)

    def _enforce_list(self, k, t):
        if k not in self.cfg:
            return []

        if self.cfg[k] is None:
            return []
        else:
            if isinstance(self.cfg[k], list):
                for idx in range(0, len(self.cfg[k])):
                    self.cfg[k][idx] = self._enforce_type(self.cfg[k][idx], t)
                return self.cfg[k]
            else:
                return [self._enforce_type(self.cfg[k], t)]

    def normalize_fields(self):
        CFG_FIELDS = self.get_all_cfg_fields()

        if self.cfg is None:
            raise ConfigError("Invalid configuration: it's empty.")

        if not isinstance(self.cfg, dict):
            raise ConfigError(
                "Invalid configuration element: {}".format(self.cfg)
            )

        # Any unknown field?
        for f in self.cfg.keys():
            if f not in CFG_FIELDS:
                raise ConfigError(
                    "Unknown configuration field: {}".format(f)
                )

        # Mandatory fields missing?
        for f in sorted(self.get_cfg_fields()[0]):
            if f not in self.cfg:
                raise ConfigError("Missing mandatory field: {}".format(f))
            if self.cfg[f] is None:
                raise ConfigError("Mandatory field is null: {}".format(f))

        # Missing attributes are set to None
        for f in CFG_FIELDS:
            if f not in self.cfg:
                self.cfg[f] = None

    @staticmethod
    def _capitalize_first(s):
        return s[0].upper() + s[1:]


class Probe(object):
    def __init__(self, probe, af):
        # probe is element of ripe-atlas-cousteau ProbeRequest
        self.id = int(probe["id"])
        self.country_code = probe["country_code"]
        self.asn_v4 = probe["asn_v4"]
        self.asn_v6 = probe["asn_v6"]
        self.asn = probe["asn_v{}".format(af)]  # ASN for the current msm AF

    def __str__(self):
        return "probe ID {} (AS{} - {})".format(
            self.id,
            self.asn,
            self.country_code
        )


class IPCache(object):
    def __init__(self):
        self.ip_cache = None

    def setup(self, **kwargs):
        logger.debug("Initializing IP cache...")

        if "_dir" in kwargs:
            _dir = kwargs["_dir"]

        if "IP_ADDRESSES_CACHE_FILE" in kwargs:
            IP_ADDRESSES_CACHE_FILE = kwargs["IP_ADDRESSES_CACHE_FILE"]
        else:
            IP_ADDRESSES_CACHE_FILE = "{}/ip_addr.cache".format(_dir)

        if "IP_PREFIXES_CACHE_FILE" in kwargs:
            IP_PREFIXES_CACHE_FILE = kwargs["IP_PREFIXES_CACHE_FILE"]
        else:
            IP_PREFIXES_CACHE_FILE = "{}/ip_pref.cache".format(_dir)

        if "IXP_CACHE_FILE" in kwargs:
            IXP_CACHE_FILE = kwargs["IXP_CACHE_FILE"]
        else:
            IXP_CACHE_FILE = "{}/ixps.cache".format(_dir)

        try:
            self.ip_cache = IPDetailsCache(
                IP_ADDRESSES_CACHE_FILE=IP_ADDRESSES_CACHE_FILE,
                IP_PREFIXES_CACHE_FILE=IP_PREFIXES_CACHE_FILE,
                MAX_CACHE=kwargs["lifetime"],
                dont_save_on_del=True
            )
        except Exception as e:
            raise ProgramError(
                "Error while setting up the IP cache: {}".format(str(e))
            )

        try:
            if kwargs["use_ixps_info"]:
                self.ip_cache.UseIXPs(
                    WhenUse=1,
                    IXP_CACHE_FILE=IXP_CACHE_FILE
                )
        except IPDetailsCacheIXPInformationError as e:
            raise ConfigError(
                "An error occurred while setting up the IP addresses cache. "
                "IXPs information are not available at the moment; please "
                "consider setting the ip_cache.use_ixps_info to False to "
                "temporary avoid problems."
            )
        except Exception as e:
            raise ProgramError(
                "Error while setting up the IXPs cache: {}".format(str(e))
            )
        except KeyboardInterrupt:
            raise ConfigError(
                "Aborting IP cache initialization"
            )

        logger.debug("IP cache initialized.")

    def get_ip_info(self, IP):
        return self.ip_cache.GetIPInformation(IP)

    def save(self):
        if self.ip_cache:
            self.ip_cache.SaveCache()


class IPCacheManager(BaseManager):
    pass
IPCacheManager.register('IPCache', IPCache)


class LockFile(object):

    def __init__(self):
        self.fd = None
        self.path = None

    def acquire(self, path):
        if not path:
            return True

        self.path = path

        self.fd = os.open(self.path, os.O_CREAT)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (OSError, IOError) as e:
            if e.errno == errno.EAGAIN:
                return False
            else:
                raise

    def release(self):
        if self.fd:
            os.close(self.fd)
            os.remove(self.path)
