#!/usr/bin/env python
import json
try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

msm_id = 1421267
probes_list = [10080,10024,11891,12320]

url = "https://atlas.ripe.net/api/v1/measurement/{}/".format(msm_id)
meta_data = json.loads(urlopen(url).read().decode("utf-8"))

url = "https://atlas.ripe.net/api/v2/measurements/{}/latest?format=json&probe_ids={}".format(msm_id, ",".join(map(str,probes_list)))
results = json.loads(urlopen(url).read().decode("utf-8"))

url = "https://atlas.ripe.net/api/v2/probes/?format=json&id__in={}".format(",".join(map(str,probes_list)))
probes = json.loads(urlopen(url).read().decode("utf-8"))

output = {
        "filter": {
            "msm_id": msm_id,
            "probes": probes_list
        },
        "meta_data": meta_data,
        "results": results,
        "probes": probes
}

with open("{}.json".format(msm_id), "w") as f:
        f.write(json.dumps(output))
