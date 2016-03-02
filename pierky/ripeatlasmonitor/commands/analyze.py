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

from ..Config import Config
from ..Helpers import IPCache, LockFile, ProbesFilter
from ..Errors import LockError
from ..Logging import logger
from ..Monitor import Monitor
from ..Analyzer import Analyzer


def execute(args):
    logger.setup(0)

    lock_file_path = "{}/locks/main.lock".format(Config.get("var_dir"))
    lock_file = LockFile()

    if not lock_file.acquire(lock_file_path):
        raise LockError("Another instance of this program is already running.")

    try:
        ip_cache = IPCache()
        ip_cache.setup(
            _dir=Config.get("ip_cache.dir"),
            lifetime=Config.get("ip_cache.lifetime"),
            use_ixps_info=Config.get("ip_cache.use_ixps_info")
        )

        if args.measurement_id:
            analyzer = Analyzer(
                ip_cache=ip_cache,
                msm_id=args.measurement_id,
                key=args.key
            )
        else:
            monitor = Monitor(
                args.monitor_name,
                ip_cache,
                key=args.key
            )
            analyzer = Analyzer(
                ip_cache=ip_cache,
                msm_id=monitor.msm_id,
                key=monitor.key
            )

        probes_filter = ProbesFilter(probe_ids=args.probes,
                                     countries=args.countries)
        try:
            print(analyzer.analyze(probes_filter=probes_filter, **vars(args)))
        finally:
            ip_cache.save()
    except KeyboardInterrupt:
        pass
    finally:
        lock_file.release()
