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
