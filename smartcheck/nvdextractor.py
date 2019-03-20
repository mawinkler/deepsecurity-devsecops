#!/usr/bin/python

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import json
import simplejson
import hashlib
import hmac
import sys
import os
import time
import pickle
import os.path

def extract_network_cves(feed):

    cves_list = set()
    cves_dict = {}
    notable_list = { 'NETWORK', 'ADJACENT_NETWORK' }

#    cves_list = set()
#    if os.path.isfile('cves_network.cache'):
#        with open('cves_network.cache', 'rb') as fp:
#            cves_list = pickle.load(fp)
    cves_list = {}
    if os.path.isfile('cves_network.cache'):
        with open('cves_network.cache', 'rb') as fp:
            cves_list = pickle.load(fp)


    print(' [*] Loading Feed {}...'.format(feed))
    with open(feed, 'r') as f:
        cves_dict = json.load(f)

    for impact in cves_dict.get('CVE_Items', {}):
        cve = impact.get('cve', {}).get('CVE_data_meta', {}).get('ID', {})
        attack_vectorV2 = impact.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('accessVector', {})
        attack_vectorV3 = impact.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('attackVector', {})
        base_scoreV2 = impact.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', {})
        base_scoreV3 = impact.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', {})

        print("{} {} {}".format(cve, attack_vectorV2, attack_vectorV3))

        if str(attack_vectorV2) in notable_list:
            cves_list[str(cve)] = str(base_scoreV2)
        if str(attack_vectorV3) in notable_list:
            cves_list[str(cve)] = str(base_scoreV3)

    # dump table to file
    print(' [*] Writing Feed...')
    with open('cves_network.cache', 'wb') as fp:
        pickle.dump(cves_list, fp)

    return cves_list

def run_module():

    for feed_file in os.listdir("."):
        if feed_file.startswith("nvdcve-1.0") and feed_file.endswith(".json"):
            extract_network_cves(feed_file)

def main():
    if (run_module()):
        sys.exit(-1)

if __name__ == '__main__':
    main()
