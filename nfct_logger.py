#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from xml.etree import ElementTree
from io import BytesIO
from datetime import datetime
from collections import namedtuple
import os, sys, logging

from nfct_cffi import NFCT


FlowData = namedtuple('FlowData', 'ts proto src dst sport dport')

def parse_event(ev_xml):
	etree = ElementTree.parse(BytesIO(ev_xml))

	flow = next(etree.iter())
	assert flow.attrib['type'] == 'new', ev_xml

	ts = flow.find('when')
	ts = datetime(*(int(ts.find(k).text) for k in ['year', 'month', 'day', 'hour', 'min', 'sec']))

	flow_data = dict()
	for meta in flow.findall('meta'):
		if meta.attrib['direction'] in ['original', 'reply']:
			l3, l4 = it.imap(meta.find, ['layer3', 'layer4'])
			proto = '{}/{}'.format(l3.attrib['protoname'], l4.attrib['protoname'])
			src, dst = (l3.find(k).text for k in ['src', 'dst'])
			sport, dport = (l4.find(k).text for k in ['sport', 'dport'])
			flow_data[meta.attrib['direction']] = FlowData(ts, proto, src, dst, sport, dport)

	# Fairly sure all new flows have to be symmetrical, check that
	fo, fr = op.itemgetter('original', 'reply')(flow_data)
	assert fo.proto == fr.proto\
		and fo.src == fr.dst and fo.dst == fr.src\
		and fo.sport == fr.dport and fo.dport == fr.sport,\
		flow_data

	return flow_data['original']


def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(description='conntrack event logging/audit tool.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(argv or sys.argv[1:])

	import logging
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.INFO)
	log = logging.getLogger()

	nfct = NFCT()
	src = nfct.generator(events=nfct.libnfct.NFNLGRP_CONNTRACK_NEW)
	next(src) # fd

	for ev_xml in src:
		# log.debug('Event: {}'.format(ev_xml))
		flow = parse_event(ev_xml)
		log.info('{0.proto} {0.src}/{0.sport} > {0.dst}/{0.dport}'.format(flow))


if __name__ == '__main__': sys.exit(main())
