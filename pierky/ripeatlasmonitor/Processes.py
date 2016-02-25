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

from multiprocessing import Process

from .Errors import RIPEAtlasMonitorError
from .Logging import logger
from .Monitor import Monitor


class RunMonitorProcess(Process):
    def __init__(self, monitor_name, ip_cache):
        Process.__init__(self, name=monitor_name)
        self.monitor_name = monitor_name
        self.ip_cache = ip_cache
        self.name = self.monitor_name

        self.monitor = None

    def run(self):
        logger.info(
            "Starting process {} (PID {})".format(
                self.name, self.pid
            )
        )
        try:
            self.monitor = Monitor(self.monitor_name, self.ip_cache)
            self.monitor.run()
        except KeyboardInterrupt:
            pass
        except RIPEAtlasMonitorError as e:
            logger.error(e)
        except Exception as e:
            logger.error(e, exc_info=True)
        logger.info("Process {} completed.".format(str(self.monitor_name)))
