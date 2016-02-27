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

from copy import deepcopy
import json

MSM_Ping_IPv6_Ongoing = 0
MSM_Traceroute_IPv6_Ongoing = 1
MSM_Ping_IPv6_Stopped = 2
MSM_Results_Traceroute_IPv4 = 3082698
MSM_Results_Ping_IPv4 = 3359986
MSM_Results_SSLCert = 1443162
MSM_Results_DNS = 1421267
MSM_Results_Traceroute_Big = 1033154
MSM_Results_DNS_NSID = 1071935

# meta_data: https://atlas.ripe.net/api/v1/measurement/<msm_id>/
# results: 'https://atlas.ripe.net/api/v2/measurements/<msm_id>/latest?format=json&probes=123,456'
# probes: 'https://atlas.ripe.net/api/v2/probes/?format=json&id__in=123,456'

MSMS = {
    # ping, IPv6, Ongoing
    str(MSM_Ping_IPv6_Ongoing): {
        "meta_data": {
            "id":0,"description":"Ping IPv6","af":6,"destination_address":"2001:DB8::1","destination_asn":65551,"destination_name":"test1.example.com","interval":240,"spread":None,"is_oneoff":False,"is_public":True,"resolve_on_probe":False,"start_time":1451606400,"stop_time":None,"creation_time":1451606400,"resolved_ips":["2001:DB8::1"],"probes_requested":1,"probes_scheduled":1,"probes_currently_involved":None,"is_all_scheduled":True,"status":{"id":2,"name":"Ongoing"},"participant_count":1,"packets":3,"size":48,"type":{"id":3,"name":"ping","af":6},"result":"https://atlas.ripe.net/api/v2/measurements/0/results?format=json"
        }
    },

    # traceroute, IPv6, Ongoing
    str(MSM_Traceroute_IPv6_Ongoing): {
        "meta_data": {
            "description":"Traceroute IPv6","af":6,"interval":100,"spread":None,"is_oneoff":True,"is_public":True,"resolve_on_probe":False,"start_time":1451606400,"stop_time":None,"creation_time":1451606400,"resolved_ips":["2001:DB8::1"],"status":{"id":2,"name":"Ongoing"},"participant_count":0,"response_timeout":4000,"protocol":"ICMP","paris":16,"size":40,"type":{"id":2,"name":"traceroute","af":4},"all_scheduling_requests_fulfilled":True,"result":"/api/v1/measurement/1/result","dst_addr":"2001:DB8::1","dst_name":"test1.example.com","dst_asn":65551,"msm_id":1,"maxhops":32,"firsthop":1
        }
    }
}

# ping, IPv6, Stopped
MSMS[str(MSM_Ping_IPv6_Stopped)] = deepcopy(MSMS[str(MSM_Ping_IPv6_Ongoing)])
MSMS[str(MSM_Ping_IPv6_Stopped)]["meta_data"]["status"] = {
    "id": 4,
    "name": "Stopped"
}

def load_data(msm_id):
    global MSMS
    with open("tests/data/{}.json".format(msm_id), "r") as f:
        MSMS[str(msm_id)] = json.load(f)

load_data(MSM_Results_Traceroute_IPv4)
load_data(MSM_Results_Ping_IPv4)
load_data(MSM_Results_SSLCert)
load_data(MSM_Results_DNS)
load_data(MSM_Results_Traceroute_Big)
load_data(MSM_Results_DNS_NSID)
