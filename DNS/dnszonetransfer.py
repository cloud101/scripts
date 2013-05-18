#!/usr/bin/env python

import dns.query,dns.zone,dns.resolver,sys,socket
from argparse import ArgumentParser
parser = ArgumentParser(description="Shellcode generator")
parser.add_argument("-d","--domain",dest="hostname", help="Provide a hostname", required=True,type=str )
args = vars(parser.parse_args())
hostname = args["hostname"]


def getNameServers(hostname):
	nameservers = dns.resolver.query(hostname, 'NS')
	return nameservers


def transferZones(nameservers,hostname):
	for nameserver in nameservers:
		try:
			xfr = dns.zone.from_xfr(dns.query.xfr(str(nameserver),hostname))
			names = xfr.nodes.keys()
			names.sort()
			for name in names:
				print xfr[name].to_text(name)
		except:
			print "Something went terribly wrong and everything crashed and burned for "+str(nameserver)

nameservers = getNameServers(hostname)
transferZones(nameservers,hostname)
