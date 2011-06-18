#!/usr/bin/env python2

import config

import json
import re
import httplib
import base64
import string
import sys
import operator

def get_json(server, user, passwd):
    params = {'version': 1.1, 'method': 'name_scan', 'params': ['', 21474836487], 'id': 1}
    auth = 'Basic ' + string.strip(base64.encodestring(user + ':' + passwd))
    headers = {"Content-type": "application/json", "Authorization": auth}
    conn = httplib.HTTPConnection(server)
    conn.request("POST", "/", json.dumps(params), headers)
    response = conn.getresponse()

    if response.status == 200:
        data = response.read()
        return data

    return None

def isValidHostElem(hostname):
    allowed = re.compile("(?!-)[a-z\d-]{1,63}(?<!-)$")
    return allowed.match(hostname)

def isValidHostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1:] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[a-z\d-]{1,63}(?<!-)$")
    return all(allowed.match(x) for x in hostname.split("."))

def isValidNCHost(hostname):
    if len(hostname) < 2:
        return False

    if hostname[:2] != 'd/':
        return False

    return isValidHostElem(hostname[2:])

data = get_json(config.SERVER, config.USER, config.PASSWD)

if data is None:
    sys.exit(1)

data = json.loads(data)['result']

data = sorted(data, key=operator.itemgetter('expires_in'))

print '<h1>expiring within 100 blocks:</h1>'

for item in data:
    if item['expires_in'] > 0 and item['expires_in'] <= 100 and isValidNCHost(item['name']):
        print item['expires_in'], item['name'][2:], '<br />'

print '<h1>expired names:</h1>'

for item in data:
    if item['expires_in'] <= 0 and isValidNCHost(item['name']):
        print item['expires_in'], item['name'][2:], '<br />'
