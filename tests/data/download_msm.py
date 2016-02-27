#!/usr/bin/env python
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

import json

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

msm_id = 1071935
probes_list = [10045, 10048, 10102, 10540, 11523]

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
