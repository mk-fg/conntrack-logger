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

Unlike e.g. [netstat-monitor](https://github.com/stalexan/netstat-monitor/), it
doesn't poll `/proc/net/*` paths (though still uses them to map flow back to
pid), getting "new flow" events via libnetfilter_conntrack (netlink socket)
instead, in a bit more efficient manner.



Usage
--------------------

Just run nfct_logger.py and get the entries from its stdout (lines wrapped for readability):

```console
# ./nfct_logger.py -p tcp
1373127181: ipv6/tcp 2001:470:1f0b:11de::12/55446 > 2607:f8b0:4006:802::1010/80 ::
	2354 1000:1000 /user/1000.user/1.session/systemd-1196/enlightenment.service ::
	curl -s -o /dev/null ipv6.google.com
1373127199: ipv4/tcp 192.168.0.12/34870 > 195.24.232.208/80 ::
	28865 1000:1000 /user/1000.user/1.session/systemd-1196/dbus.service ::
	python /usr/libexec/dbus-lastfm-scrobbler
1373127220: ipv4/tcp 127.0.0.1/59047 > 127.0.0.1/1234 ::
	2387 1000:1000 /user/1000.user/1.session/systemd-1196/enlightenment.service ::
	ncat -v cane 1234
```

Default log format (can be controlled via --format, timestamp format via --format-ts) is (wrapped):

	{ts}: {ev.proto} {ev.src}/{ev.sport} > {ev.dst}/{ev.dport} ::
		{info.pid} {info.uid}:{info.gid} {info.service} :: {info.cmdline}

Info about pid might not be available for transient connections, like one-way
udp packets, as these don't seem to end up in /proc/net/udp (or udp6) tables,
hence it's hard to get socket "inode" number.

As netfilter, conntrack and netlink sockets are linux-specific things (afaik),
script should not work on any other platforms, unless there is some
compatibility layer in place.


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



Installation
--------------------

It's a regular package for Python 2.7 (not 3.X), but not in pypi, so can be
installed from a checkout with something like that:

	% python setup.py install

Better way would be to use [pip](http://pip-installer.org/) to install all the
necessary dependencies as well:

	% pip install 'git+https://github.com/mk-fg/conntrack-logger.git#egg=conntrack-logger'

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use "install --user",
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.

Alternatively, `./nfct_logger.py` can be run right from the checkout tree
without any installation.

### Requirements

* Python 2.7 (not 3.X)
* [CFFI](http://cffi.readthedocs.org) (for libnetfilter_conntrack bindings)
* [libnetfilter_conntrack](http://www.netfilter.org/projects/libnetfilter_conntrack)
* nf_conntrack_netlink kernel module (e.g. `modprobe nf_conntrack_netlink`)

CFFI uses C compiler to generate bindings, so gcc (or other compiler) should be
available if module is being built from source or used from checkout tree.



Limitations
--------------------

When new flow event is received from libnetfilter_conntrack, it
[doesn't have "pid" attribute](https://git.netfilter.org/libnetfilter_conntrack/tree/include/libnetfilter_conntrack/libnetfilter_conntrack.h#n62)
associated with it, so script looks up corresponding line in `/proc/net/*` to
pick "inode" number for connection from there, then does
`glob('/proc/[0-9]*/fd/[0-9]*')`, readlink() on each to find which one leads to
socket matching that inode and then grabs/prints info for the pid from there on
match.

So for super-quick connections, slow pid context switching, lots of pids or
something, it might fail to match socket/pid in time, while both are still
around, printing only connection info instead.

Running curl on even the fastest url probably won't ever slip by the logging,
but some fast app opening socket, sending a packet, then closing it immediately
afterwards can do that.

[auditd](https://people.redhat.com/sgrubb/audit) is probably a tool to track
such things in a more dedicated way.
