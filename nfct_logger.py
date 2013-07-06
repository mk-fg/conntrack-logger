#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, logging

from nfct_cffi import NFCT


def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(description='conntrack event logging/audit tool.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(argv or sys.argv[1:])

	import logging
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	src = NFCT().generator()
	next(src) # fd
	for data in src:
		log.debug('Event: {}'.format(data))


if __name__ == '__main__': sys.exit(main())
