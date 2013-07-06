#!/usr/bin/env python

import os, sys

from distutils.core import setup

# Error-handling here is to allow package to be built w/o README included
try:
	readme = open(os.path.join(
		os.path.dirname(__file__), 'README.txt' )).read()
except IOError: readme = ''

from nfct_cffi import NFCT

setup(

	name = 'conntrack-logger',
	version = '13.07.0',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = [
		'nfct', 'conntrack', 'flow', 'connection', 'traffic', 'analysis',
		'analyze', 'network', 'linux', 'security', 'track', 'netfilter',
		'audit', 'cffi', 'libnetfilter_conntrack', 'netlink', 'socket' ],
	url = 'http://github.com/mk-fg/conntrack-logger',

	description = 'Tool to log conntrack flows and associated process/service info',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Intended Audience :: Developers',
		'Intended Audience :: System Administrators',
		'Intended Audience :: Telecommunications Industry',
		'License :: OSI Approved',
		'Operating System :: POSIX :: Linux',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Security',
		'Topic :: System :: Networking :: Monitoring',
		'Topic :: System :: Operating System Kernels :: Linux' ],

	ext_modules = [NFCT().ffi.verifier.get_extension()],

	py_modules = ['nfct_cffi', 'nfct_logger'],
	package_data = {'': ['README.txt']},

	entry_points = {
		'console_scripts': ['conntrack-logger = nfct_logger:main'] })
