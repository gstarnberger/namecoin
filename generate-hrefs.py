#!/usr/bin/env python2

import config

import json
import re
import socket
import httplib
import base64
import string
import sys

# this script has been quickly hacked together from the source of
# generate-maradns-config.py. you probably don't want to use it (in it's
# current form).

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
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return allowed.match(hostname)

def isValidHostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1:] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

data = get_json(config.SERVER, config.USER, config.PASSWD)

if data is None:
    sys.exit(1)

data = json.loads(data)['result']

# print "% NS bitname0.sysfrog.org. ~"
# print "% NS bitname1.sysfrog.org. ~"
# print "% A 178.63.239.23 ~"

print """<html>
<head><title>list of direct bitname.org mappings</title></head>
<body>"""

for item in data:
    name = item['name']

    if name.startswith('d/'):
        name = name[2:]

        if isValidHostElem(name):

            try:
                payload = json.loads(item['value'])

                if payload != [] and payload.has_key('map'):
                    mapping = payload['map']

                    if mapping.has_key(''):
                        root = mapping['']

                        if type(root) == type({}) and root.has_key('ns'):
                            ns = root['ns']

                            if type(ns) == type([]):
                                for server in ns:
                                    if isValidHostname(server):
                                        if not server.endswith('.'):
                                            server = server + '.'
                                        # print "%s.%% NS %s ~" % (name, server)
                                        continue

                        elif type(root) == type('') or type(root) == type(u''):
                            try:
                                ip = socket.inet_ntoa(socket.inet_aton(root))
                                # print "%s.%% A %s ~" % (name, ip)
                                # print "*.%s.%% A %s ~" % (name, ip)
                                print '<a href="http://%s.bitname.org/">%s.bitname.org</a><br />' % (name, name)
                            except socket.error:
                                pass

                    for key in mapping.keys():
                        if key == '':
                            continue

                        root = mapping[key]

                        if (type(root) == type('') or type(root) == type(u'')) and isValidHostElem(key):
                            try:
                                ip = socket.inet_ntoa(socket.inet_aton(root))
                                # print "%s.%s.%% A %s ~" % (key, name, ip)
                            except socket.error:
                                pass

            except ValueError:
                pass

print "</body></html>"
