from ..Config import Config
from ..Helpers import IPCache
from ..Monitor import Monitor


def execute(args):
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
