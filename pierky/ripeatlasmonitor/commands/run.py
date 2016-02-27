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
from ..Helpers import IPCache, IPCacheManager, LockFile, ProbesFilter
from ..Logging import logger
from ..Monitor import Monitor
from ..Processes import RunMonitorProcess
from ..Errors import ArgumentError, LockError


def run_one(args):
    ip_cache = IPCache()
    ip_cache.setup(
        _dir=Config.get("ip_cache.dir"),
        lifetime=Config.get("ip_cache.lifetime"),
        use_ixps_info=Config.get("ip_cache.use_ixps_info")
    )

    monitor = Monitor(
        args.monitor_name,
        ip_cache,
        msm_id=args.measurement_id,
        key=args.key
    )

    if args.stream:
        monitor.stream = args.stream

        if args.stream_timeout:
            monitor.stream_timeout = args.stream_timeout

    if monitor.stream:
        if args.start_time or args.stop_time or args.latest_results or \
                args.dont_wait:

            raise ArgumentError(
                "The 'Results timeframe' arguments (--start-time, --stop-time "
                "and so on) can't be used for monitors which use "
                "results streaming."
            )

    probes_filter = ProbesFilter(probe_ids=args.probes,
                                 countries=args.countries)

    monitor.run(start=args.start_time, stop=args.stop_time,
                latest_results=args.latest_results,
                dont_wait=args.dont_wait, probes_filter=probes_filter)


def run_multiple(args):

    def join_processes(timeout=None):
        someone_still_alive = False
        for process in processes:
            if process.is_alive():
                someone_still_alive = True

                if timeout:
                    logger.info(
                        "Waiting {} more seconds for process {} "
                        "(PID {}) to terminate...".format(
                            timeout, process.name, process.pid
                        )
                    )
                    process.join(timeout=timeout)
                else:
                    # wait for a small amount of time (and not forever)
                    # so that processes that completed their execution
                    # can be joined even if the previous ones are still
                    # running
                    process.join(timeout=5)

        return someone_still_alive

    manager = IPCacheManager()
    manager.start()
    ip_cache = manager.IPCache()
    ip_cache.setup(
        _dir=Config.get("ip_cache.dir"),
        lifetime=Config.get("ip_cache.lifetime"),
        use_ixps_info=Config.get("ip_cache.use_ixps_info")
    )

    processes = []
    for monitor_name in args.monitor_name:
        process = RunMonitorProcess(monitor_name, ip_cache)
        processes.append(process)
        process.start()

    try:
        while join_processes():
            pass
    except KeyboardInterrupt:
        try:
            join_processes(timeout=10)
        except Exception as e:
            logger.error(str(e), exc_info=True)
    except Exception as e:
        logger.error(str(e), exc_info=True)

    logger.info("Main process completed.")


def run(args):
    logger.setup(args.verbose or Config.get("verbosity"),
                 stdout=args.command == "run")

    if args.command == "run":
        run_one(args)
    else:
        run_multiple(args)


def execute(args):
    lock_file_path = "{}/locks/main.lock".format(Config.get("var_dir"))
    lock_file = LockFile()

    if not lock_file.acquire(lock_file_path):
        raise LockError("Another instance of this program is already running.")

    try:
        run(args)
    except KeyboardInterrupt:
        pass
    finally:
        lock_file.release()
