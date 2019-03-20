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
import re

def run_module():

    cves_list = set()
    if os.path.isfile('cves_network.cache'):
        with open('cves_network.cache', 'rb') as fp:
            cves_list = pickle.load(fp)

    print("Authenticating to Smart Check engine at "
          + os.environ["DSSC_SERVICE"])
    url = os.environ["DSSC_SERVICE"] + "/api/sessions"
    data = {
        "user": {
            "userid": os.environ["DSSC_USERNAME"],
            "password": os.environ["DSSC_PASSWORD"]
            }
        }

    post_header = {
        "Content-type": "application/json",
        "x-argus-api-version": "2017-10-16"
        }
    response = requests.post(url,
                             data=json.dumps(data),
                             headers=post_header,
                             verify=False
                             ).json()

    if 'message' in response:
        print("Authentication response: " + response['message'])
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError(
                "Invalid DSSC credentials or SmartCheck not available"
                )

    response_token = response['token']

    response_scanId = os.environ["SCANID"]
    print("Scan ID: " + response_scanId)

    print("Query Report")
    url = os.environ["DSSC_SERVICE"] + "/api/scans/" + response_scanId
    data = { }
    post_header = {
        "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
        "authorization": "Bearer " + response_token
        }
    response = requests.get(url,
                            data=json.dumps(data),
                            headers=post_header,
                            verify=False
                            ).json()

    with open('' + response_scanId +'.json', 'w') as f:
        json.dump(response, f)

    # Error handling
    if 'message' in response:
        print("Query report response: " + response['message'])
        if response['message'] == "Invalid DSSC credentials":
            raise ValueError(
                "Invalid DSSC credentials or SmartCheck not available")

    # iterate layers
    notable_list = { 'defcon1', 'critical', 'high' }
    result_list = response['details'].get('results', {})

    print("\nAttack Vector\tCVE")
    print("--------------------------------")
    for result in result_list:
        if 'vulnerabilities' in result:

            url = os.environ["DSSC_SERVICE"] + result.get('vulnerabilities', {}) + "?limit=10000"
            data = { }
            post_header = {
                "Content-type": "application/vnd.com.trendmicro.argus.webhook.v1+json",
                "authorization": "Bearer " + response_token,
                }
            response_layer = requests.get(url,
                                          data=json.dumps(data),
                                          headers=post_header,
                                          verify=False
                                          ).json()

            with open('' + re.search(r"(?<=sha256:).*?(?=/vul)", result.get('vulnerabilities', {})).group(0) +'.json', 'w') as f:
                json.dump(response_layer, f)

            for item in response_layer.get('vulnerabilities', {}):
                affected=item.get('name', {})
                for vul in item.get('vulnerabilities', {}):
#                    if vul.get('severity', {}) in notable_list:
                        attack_vector = ""
                        if vul.get('name', {}) in cves_list:
                            attack_vector = "NETWORK"
                        print("{}\t\t{}".format(attack_vector,
                                              vul.get('name', {})
                                              )
                              )

    # export scan report
    with open('scan_report.json', 'w') as f:
        json.dump(response, f)

def main():
    if (run_module()):
        sys.exit(-1)

if __name__ == '__main__':
    main()
