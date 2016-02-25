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

msm_id = 1033154
probes_list = [3564, 4102, 2866, 11308, 3161, 11675, 2673, 10070, 3036, 12081, 11106, 2101, 4203, 4746, 3157, 3082, 4777, 10886, 11877, 4401, 12482, 11125, 4557, 4135, 12189, 11815, 11132, 3735, 3319, 4916, 2144, 11684, 10233, 4532, 10611, 12266, 4206, 11168, 2115, 2523, 11208, 10098, 10928, 10616, 4553, 10935, 12211, 4617, 2060, 2748, 2736, 10904, 11318, 11148, 10180, 11473, 10029, 10012, 11194, 12015, 12666, 10644, 10037, 10015, 4015, 11458, 3999, 4844, 10622, 2864, 11206, 12291, 4780, 10888, 11905, 2288, 4821, 2178, 12175, 4618, 10890, 11719, 4484, 11476, 11587, 10735, 3919]

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
