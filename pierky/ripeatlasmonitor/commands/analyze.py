from ..Config import Config
from ..Helpers import IPCache, LockFile
from ..Errors import LockError
from ..Logging import logger
from ..Monitor import Monitor


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
        monitor = Monitor({
            "measurement-id": args.measurement_id,
            "key": args.key,
            "matching_rules": [{}]
        }, ip_cache)

        print("Downloading and processing results... please wait")
        print(monitor.analyze(**vars(args)))
    except KeyboardInterrupt:
        pass
    finally:
        lock_file.release()
