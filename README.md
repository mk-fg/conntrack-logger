conntrack-logger
--------------------

Tool to make best effort to log conntrack flows along with associated pids,
which service cgroup they belong to and misc other info about them.

Think of it as an auditd extension to log network connections.

Main purpose is to keep track of what (if anything) in the system tries to
establish fishy or unauthorized connections.

For example, imagine your IDS spots a occasional (e.g. 1 per day/week)
connections to known botnet hosts from one of the intranet machines.
You get a dump of some encrypted traffic that gets passed, but looking at the
machine in question, you've no idea which pid initiated these at the time - only
clue is transient port numbers, which are useful only while connection lasts.

This tool allows to attribute such logged connections to pids (which might be
e.g. forked curl, hence not useful by itself) and services they belong to,
assuming proper service-pid-tracking system (i.e. systemd cgroups) is in place.



Usage
--------------------

Soon.


### nfct_cffi

Tool is based on bundled nfct_cffi module, which can be used from any python
code:

```python
from nfct_cffi import NFCT

src = NFCT().generator()
print 'Netlink fd: {} (to e.g. integrate into eventloop)'.format(next(src))
for data in src:
	print 'Got event: {}'.format(data)
```

Module uses libnetfilter_conntrack via CFFI.
