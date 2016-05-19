#!/usr/bin/env python2
#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, signal

from cffi import FFI


# Try to work around insane "write_table" operations (which assume that
#  they can just write lextab.py and yacctab.py in current dir), used by default.
try: from ply.lex import Lexer
except ImportError: pass
else: Lexer.writetab = lambda s,*a,**k: None
try: from ply.yacc import LRGeneratedTable
except ImportError: pass
else: LRGeneratedTable.write_table = lambda s,*a,**k: None


# There're no defs for conntrack-expectations' handling here
# Also nfct_nfnlh() can be useful here for e.g. nfnl_rcvbufsiz()
_cdef = '''
typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;

static const u_int8_t NFNL_SUBSYS_NONE;
static const u_int8_t NFNL_SUBSYS_CTNETLINK;

static const unsigned int NFNLGRP_NONE;
static const unsigned int NFNLGRP_CONNTRACK_NEW;
static const unsigned int NFNLGRP_CONNTRACK_UPDATE;
static const unsigned int NFNLGRP_CONNTRACK_DESTROY;

enum nf_conntrack_msg_type {
	NFCT_T_UNKNOWN,
	NFCT_T_NEW,
	NFCT_T_UPDATE,
	NFCT_T_DESTROY,
	NFCT_T_ALL,
	NFCT_T_ERROR,
	...
};

enum nfct_cb {
	NFCT_CB_FAILURE,
	NFCT_CB_STOP,
	NFCT_CB_CONTINUE,
	NFCT_CB_STOLEN,
	...
};

enum nfct_o {
	NFCT_O_PLAIN,
	NFCT_O_DEFAULT,
	NFCT_O_XML,
	NFCT_O_MAX,
	...
};

enum nfct_of {
	NFCT_OF_SHOW_LAYER3,
	NFCT_OF_TIME,
	NFCT_OF_ID,
	NFCT_OF_TIMESTAMP,
	...
};

struct nfct_handle* nfct_open(u_int8_t subsys_id, unsigned int subscriptions);
int nfct_close(struct nfct_handle * cth);
int nfct_fd(struct nfct_handle *cth);

struct nlmsghdr {
	u_int32_t nlmsg_len; /* Length of message including header */
	u_int16_t nlmsg_type; /* Message content */
	u_int16_t nlmsg_flags; /* Additional flags */
	u_int32_t nlmsg_seq; /* Sequence number */
	u_int32_t nlmsg_pid; /* Sending process port ID */
};

typedef int nfct_callback(
	const struct nlmsghdr *nlh,
	enum nf_conntrack_msg_type type,
	struct nf_conntrack *ct, void *data );

int nfct_callback_register2(
	struct nfct_handle *h,
	enum nf_conntrack_msg_type type,
	nfct_callback *cb, void *data );

void nfct_callback_unregister2(struct nfct_handle *h);

int nfct_catch(struct nfct_handle *h);

int nfct_snprintf(
	char *buf,
	unsigned int size,
	const struct nf_conntrack *ct,
	const unsigned int msg_type,
	const unsigned int out_type,
	const unsigned int out_flags );
'''

_clibs_includes = '''
#include <sys/types.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
'''
_clibs_link = 'nfnetlink', 'netfilter_conntrack'


class NFCTError(OSError): pass

NFWouldBlock = type('NFWouldBlock', (object,), dict())


class NFCT(object):

	_instance = None

	def __new__(cls):
		if not cls._instance:
			cls._instance = super(NFCT, cls).__new__(cls)
		return cls._instance

	def __init__(self):
		global _cdef, _clibs_includes, _clibs_link
		self.ffi = FFI()
		self.ffi.cdef(_cdef)
		self.libnfct = self.ffi.verify(_clibs_includes, libraries=list(_clibs_link))
		self.libnfct_cache = dict()
		_cdef = _clibs_includes = _clibs_link = None


	def _ffi_call( self, func, args,
			no_check=False, check_gt0=False, check_notnull=False ):
		'''Call lib function through cffi,
				checking return value and raising error, if necessary.
			Checks if return is >0 by default.'''
		res = func(*args)
		if no_check\
			or (check_gt0 and res > 0)\
			or (check_notnull and res)\
			or res >= 0: return res
		errno_ = self.ffi.errno
		raise NFCTError(errno_, os.strerror(errno_))

	def __getattr__(self, k):
		if not (k.startswith('nfct_') or k.startswith('c_')):
			return super(NFCT, self).__getattr__(k)
		if k.startswith('c_'): k = k[2:]
		if k not in self.libnfct_cache:
			func = getattr(self.libnfct, k)
			self.libnfct_cache[k] = lambda *a,**kw: self._ffi_call(func, a, **kw)
		return self.libnfct_cache[k]


	def generator(self, events=None, output_flags=None, handle_sigint=True):
		'''Generator that yields:
				- on first iteration - netlink fd that can be poll'ed
					or integrated into some event loop (twisted, gevent, ...).
					Also, that is the point where uid/gid/caps can be dropped.
				- on all subsequent iterations it does recv() on that fd,
					yielding XML representation of the captured conntrack event.
			Keywords:
				events: mask for event types to capture
					- or'ed NFNLGRP_CONNTRACK_* flags, None = all.
				output_flags: which info will be in resulting xml
					- or'ed NFCT_OF_* flags, None = set all.
				handle_sigint: add SIGINT handler to process it gracefully.'''

		if events is None:
			events = (
				self.libnfct.NFNLGRP_CONNTRACK_NEW |
				self.libnfct.NFNLGRP_CONNTRACK_UPDATE |
				self.libnfct.NFNLGRP_CONNTRACK_DESTROY )
		if output_flags is None:
			output_flags = (
				self.libnfct.NFCT_OF_TIME |
				self.libnfct.NFCT_OF_ID |
				self.libnfct.NFCT_OF_SHOW_LAYER3 |
				self.libnfct.NFCT_OF_TIMESTAMP )

		handle = self.nfct_open(
			self.libnfct.NFNL_SUBSYS_NONE, events, check_notnull=True )

		cb_results = list()
		xml_buff_size = 2048 # ipv6 events are ~1k
		xml_buff = self.ffi.new('char[]', xml_buff_size)

		@self.ffi.callback('nfct_callback')
		def recv_callback(handler, msg_type, ct_struct, data):
			try:
				size = self.nfct_snprintf( xml_buff, xml_buff_size, ct_struct,
					msg_type, self.libnfct.NFCT_O_XML, output_flags, check_gt0=True )
				assert size <= xml_buff_size, size # make sure xml fits
				data = self.ffi.buffer(xml_buff, size)[:]
				cb_results.append(data)
			except:
				cb_results.append(StopIteration) # breaks the generator
				raise
			return self.libnfct.NFCT_CB_STOP # to yield processed data from generator

		if handle_sigint:
			global _sigint_raise
			_sigint_raise = False
			def sigint_handler(sig, frm):
				global _sigint_raise
				_sigint_raise = True
				cb_results.append(StopIteration)
			sigint_handler = signal.signal(signal.SIGINT, sigint_handler)

		def break_check(val):
			if val is StopIteration: raise val()
			return val

		self.nfct_callback_register2(
			handle, self.libnfct.NFCT_T_ALL, recv_callback, self.ffi.NULL )
		try:
			peek = break_check((yield self.nfct_fd(handle))) # yield fd for poll() on first iteration
			while True:
				if peek:
					peek = break_check((yield NFWouldBlock)) # poll/recv is required
					continue
				# No idea how many times callback will be used here
				self.nfct_catch(handle)
				if handle_sigint and _sigint_raise: raise KeyboardInterrupt()
				# Yield individual events
				for result in cb_results:
					break_check(result)
					peek = break_check((yield result))
				cb_results = list()

		finally:
			if handle_sigint: signal.signal(signal.SIGINT, sigint_handler)
			self.nfct_callback_unregister2(handle, no_check=True)
			self.nfct_close(handle)


if __name__ == '__main__':
	src = NFCT().generator()
	print('Netlink fd: {}, started logging conntrack events'.format(next(src)))
	for data in src:
		print('Event: {}'.format(data))
