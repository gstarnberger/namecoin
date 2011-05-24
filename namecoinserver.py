#!/usr/bin/env python2

from twisted.names import dns, server, client, cache, error
from twisted.application import service, internet
from twisted.python import log

import json


class JSONMapping(object):
    mapping = {}

    def __init__(self):
        data = json.load(open('names.txt'))

        for item in data:
            name = item['name']
            if name.startswith('d/'):
                name = name[2:]

                try:
                    payload = json.loads(item['value'])

                    if payload != [] and 'map' in payload:
                        self.mapping[name] = payload['map']

                except ValueError:
                    pass

    def query(self, name):
        return self.mapping[name]


class MapResolver(client.Resolver):
    def __init__(self, mapping, servers, me):
        self.me = '.' + me
        self.me_len = len(me.split('.'))
        self.mapping = mapping
        client.Resolver.__init__(self, servers=servers)
        self.ttl = 10

    def lookupAddress(self, name, timeout=None):

        def add_header(name, type, record, auth=False):
            return dns.RRHeader(name, type, dns.IN, self.ttl, record, auth)

        def add_frame(records):
            return [records, (), ()]

        if not name.endswith(self.me):
            raise error.DNSNameError("Invalid name")

        local_part = name.split('.')[:self.me_len * -1]

        local_domain = local_part[-1]
        local_local = '.'.join(local_part[:-1])

        query_data = self.mapping.query(local_domain)

        ldata = None

        if local_local in query_data:
            # specific subdomain has been queried
            ldata = query_data[local_local]
        elif '' in query_data:
            # fallback to default mapping
            ldata = query_data['']

        if ldata is not None:
            if type(ldata) == type(u'') or type(ldata) == type(''):
                return add_frame((add_header(name, dns.A, dns.Record_A(ldata), auth=True), ))
            elif type(ldata) == type({}):
                if 'translate' in ldata and 'ns' in ldata:
                    pass  # TODO
                elif 'ns' in ldata:
                    ns = ldata['ns']
                    return add_frame([add_header(local_domain + self.me, dns.NS, dns.Record_NS(x), auth=True) for x in ns])

        log.msg("something undefined happened")

        raise error.DNSServerError("Undefined error")

application = service.Application('dnsserver', 1, 1)

json_mapping = JSONMapping()

resolver = MapResolver(mapping=json_mapping, servers=[('8.8.8.8', 53)], me='bitname.org')

f = server.DNSServerFactory(caches=[cache.CacheResolver()], clients=[resolver])
p = dns.DNSDatagramProtocol(f)
f.noisy = p.noisy = False

ret = service.MultiService()
PORT = 53

for (klass, arg) in [(internet.TCPServer, f), (internet.UDPServer, p)]:
    s = klass(PORT, arg)
    s.setServiceParent(ret)

ret.setServiceParent(service.IServiceCollection(application))

if __name__ == '__main__':
    import sys
    print "Usage: twistd -y %s" % sys.argv[0]
