#  Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
# 	The Regents of the University of California.  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that: (1) source code distributions
#  retain the above copyright notice and this paragraph in its entirety, (2)
#  distributions including binary code include the above copyright notice and
#  this paragraph in its entirety in the documentation or other materials
#  provided with the distribution, and (3) all advertising materials mentioning
#  features or use of this software display the following acknowledgement:
#  ``This product includes software developed by the University of California,
#  Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
#  the University nor the names of its contributors may be used to endorse
#  or promote products derived from this software without specific prior
#  written permission.
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
# @(#) $Header: /tcpdump/master/tcpdump/Makefile.in,v 1.325 2008-11-21 23:17:26 guy Exp $ (LBL)

#
# Various configurable paths (remember to edit Makefile.in, not Makefile)
#

# Top level hierarchy
prefix = /usr/local
exec_prefix = ${prefix}
datarootdir = ${prefix}/share
# Pathname of directory to install the binary
sbindir = ${exec_prefix}/sbin
# Pathname of directory to install the man page
mandir = ${datarootdir}/man

# VPATH
srcdir = .


#
# You shouldn't need to edit anything below here.
#

CC = gcc
MKDEP = 
PROG = tcpdump
CCOPT =  -ffloat-store
INCLS = -I. -I/usr/include  -I./missing
DEFS = -DHAVE_CONFIG_H  -I./missing  -D_U_="__attribute__((unused))"

# Standard CFLAGS
CFLAGS = -DINET6 -g -O2
FULL_CFLAGS = $(CCOPT) $(DEFS) $(INCLS) $(CFLAGS)

# Standard LDFLAGS
LDFLAGS = 

# Standard LIBS
LIBS = -lcrypto -L/usr/lib/x86_64-linux-gnu  -lpcap 

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
RANLIB = ranlib

DEPENDENCY_CFLAG = 

# Explicitly define compilation rule since SunOS 4's make doesn't like gcc.
# Also, gcc does not remove the .o before forking 'as', which can be a
# problem if you don't own the file but can write to the directory.
.c.o:
	@rm -f $@
	$(CC) $(FULL_CFLAGS) -c $(srcdir)/$*.c

ifdef TCPDUMP_MINI

CSRC =	addrtoname.c af.c checksum.c cpack.c gmpls.c oui.c gmt2local.c ipproto.c \
        nlpid.c l2vpn.c machdep.c parsenfsfh.c in_cksum.c \
	print-802_11.c print-aodv.c print-arp.c print-ascii.c \
	print-bgp.c print-bootp.c print-cdp.c print-domain.c print-eap.c print-ether.c \
	print-gre.c print-icmp.c print-igmp.c print-ip.c \
	print-l2tp.c print-lldp.c print-llc.c \
 	print-nfs.c print-ntp.c print-null.c print-olsr.c print-ospf.c \
	print-ppp.c print-pppoe.c print-pptp.c print-radius.c print-raw.c print-rsvp.c \
	print-sctp.c print-sip.c print-sll.c print-snmp.c print-stp.c print-sunrpc.c \
	print-syslog.c print-tcp.c print-telnet.c print-tftp.c print-udp.c \
	setsignal.c tcpdump.c util.c signature.c print-ipnet.c print-forces.c

else

CSRC =	addrtoname.c af.c checksum.c cpack.c gmpls.c oui.c gmt2local.c ipproto.c \
        nlpid.c l2vpn.c machdep.c parsenfsfh.c in_cksum.c \
	print-802_11.c print-802_15_4.c print-ap1394.c print-ah.c \
	print-arcnet.c print-aodv.c print-arp.c print-ascii.c print-atalk.c \
	print-atm.c print-beep.c print-bfd.c print-bgp.c \
	print-bootp.c print-bt.c print-calm-fast.c print-carp.c print-cdp.c print-cfm.c \
	print-chdlc.c print-cip.c print-cnfp.c print-dccp.c print-decnet.c \
	print-domain.c print-dtp.c print-dvmrp.c print-enc.c print-egp.c \
	print-eap.c print-eigrp.c\
	print-esp.c print-ether.c print-fddi.c print-forces.c print-fr.c \
	print-geonet.c print-gre.c print-hsrp.c print-icmp.c print-igmp.c \
	print-igrp.c print-ip.c print-ipcomp.c print-ipfc.c print-ipnet.c \
	print-ipx.c print-isoclns.c print-juniper.c print-krb.c \
	print-l2tp.c print-lane.c print-ldp.c print-lldp.c print-llc.c \
        print-lmp.c print-lspping.c print-lwapp.c \
	print-lwres.c print-mobile.c print-mpcp.c print-mpls.c print-mptcp.c print-msdp.c \
	print-msnlb.c print-nflog.c print-nfs.c print-ntp.c print-null.c \
	print-olsr.c print-openflow.c print-openflow-1.0.c print-ospf.c \
	print-pgm.c print-pim.c \
	print-ppi.c print-ppp.c print-pppoe.c print-pptp.c \
	print-radius.c print-raw.c print-rip.c print-rpki-rtr.c print-rrcp.c print-rsvp.c \
	print-rx.c print-sctp.c print-sflow.c print-sip.c print-sl.c print-sll.c \
	print-slow.c print-snmp.c print-stp.c print-sunatm.c print-sunrpc.c \
	print-symantec.c print-syslog.c print-tcp.c print-telnet.c print-tftp.c \
	print-timed.c print-tipc.c print-token.c print-udld.c print-udp.c \
	print-usb.c print-vjc.c print-vqp.c print-vrrp.c print-vtp.c \
	print-wb.c print-zephyr.c print-zeromq.c print-vxlan.c print-otv.c signature.c setsignal.c tcpdump.c util.c

LIBNETDISSECT_SRC=print-isakmp.c
LIBNETDISSECT_OBJ=$(LIBNETDISSECT_SRC:.c=.o)
LIBNETDISSECT=libnetdissect.a

endif

LOCALSRC = print-ip6.c print-ip6opts.c print-mobility.c print-ripng.c print-icmp6.c print-frag6.c print-rt6.c print-ospf6.c print-dhcp6.c print-babel.c print-smb.c smbutil.c 
GENSRC = version.c
LIBOBJS =  ${LIBOBJDIR}strlcat$U.o ${LIBOBJDIR}strlcpy$U.o

SRC =	$(CSRC) $(GENSRC) $(LOCALSRC) $(LIBNETDISSECT_SRC)

# We would like to say "OBJ = $(SRC:.c=.o)" but Ultrix's make cannot
# hack the extra indirection
OBJ =	$(CSRC:.c=.o) $(GENSRC:.c=.o) $(LOCALSRC:.c=.o) $(LIBOBJS) $(LIBNETDISSECT_OBJ)
HDR = \
	addrtoname.h \
	af.h \
	ah.h \
	aodv.h \
	appletalk.h \
	arcnet.h \
	atm.h \
	atmuni31.h \
	bootp.h \
	bgp.h \
	chdlc.h \
	cpack.h \
	dccp.h \
	decnet.h \
	decode_prefix.h \
	enc.h \
	esp.h \
	ether.h \
	ethertype.h \
	extract.h \
	fddi.h \
	gmpls.h \
	gmt2local.h \
	icmp6.h \
	ieee802_11.h \
	ieee802_11_radio.h \
	igrp.h \
	interface.h \
	interface.h \
	ip.h \
	ip6.h \
	ipfc.h \
	ipnet.h \
	ipproto.h \
	ipsec_doi.h \
	ipx.h \
	isakmp.h \
	l2tp.h \
	l2vpn.h \
	lane.h \
	llc.h \
	machdep.h \
	mib.h \
	mpls.h \
	mptcp.h \
	nameser.h \
	netbios.h \
	netdissect.h \
	nflog.h \
	nfs.h \
	nfsfh.h \
	nlpid.h \
	ntp.h \
	oakley.h \
	openflow.h \
	ospf.h \
	ospf6.h \
	oui.h \
	pcap-missing.h \
	pmap_prot.h \
	ppi.h \
	ppp.h \
	route6d.h \
	rpc_auth.h \
	rpc_msg.h \
	rx.h \
	sctpConstants.h \
	sctpHeader.h \
	setsignal.h \
	signature.h \
	slcompress.h \
	slip.h \
	sll.h \
	smb.h \
	tcp.h \
	tcpdump-stdinc.h \
	telnet.h \
	tftp.h \
	timed.h \
	token.h \
	udp.h

TAGHDR = \
	/usr/include/arpa/tftp.h \
	/usr/include/net/if_arp.h \
	/usr/include/net/slip.h \
	/usr/include/netinet/if_ether.h \
	/usr/include/netinet/in.h \
	/usr/include/netinet/ip_icmp.h \
	/usr/include/netinet/tcp.h \
	/usr/include/netinet/udp.h \
	/usr/include/protocols/routed.h

TAGFILES = $(SRC) $(HDR) $(TAGHDR)

CLEANFILES = $(PROG) $(OBJ) $(GENSRC)

EXTRA_DIST = \
	CHANGES \
	CREDITS \
	INSTALL.txt \
	LICENSE \
	Makefile.in \
	Makefile-devel-adds \
	README.md \
	Readme.Win32 \
	VERSION \
	aclocal.m4 \
	atime.awk \
	bpf_dump.c \
	config.guess \
	config.h.in \
	config.sub \
	configure \
	configure.in \
	install-sh \
	lbl/os-osf4.h \
	lbl/os-solaris2.h \
	lbl/os-sunos4.h \
	lbl/os-ultrix4.h \
	makemib \
	missing/addrinfo.h \
	missing/dlnames.c \
	missing/datalinks.c \
	missing/getnameinfo.c \
	missing/inet_aton.c \
	missing/inet_ntop.c \
	missing/inet_pton.c \
	missing/snprintf.c \
	missing/sockstorage.h \
	missing/strdup.c \
	missing/strlcat.c \
	missing/strlcpy.c \
	missing/strsep.c \
	mkdep \
	packetdat.awk \
	pcap_dump_ftell.c \
	print-babel.c \
	print-dhcp6.c \
	print-frag6.c \
	print-icmp6.c \
	print-ip6.c \
	print-ip6opts.c \
	print-mobility.c \
	print-netbios.c \
	print-ospf6.c \
	print-pflog.c \
	print-ripng.c \
	print-rt6.c \
	print-smb.c \
	send-ack.awk \
	smbutil.c \
	stime.awk \
	strcasecmp.c \
	tcpdump.1.in \
	vfprintf.c \
	win32/Include/bittypes.h \
	win32/Include/errno.h \
	win32/Include/getopt.h \
	win32/Include/w32_fzs.h \
	win32/Src/getopt.c \
	win32/prj/GNUmakefile \
	win32/prj/WinDump.dsp \
	win32/prj/WinDump.dsw

TEST_DIST= `find tests \( -name 'DIFF' -prune \) -o \( -name NEW -prune \) -o -type f \! -name '.*' \! -name '*~' -print`

all: $(PROG)

$(PROG): $(OBJ) 
	@rm -f $@
	$(CC) $(FULL_CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

ifndef TCPDUMP_MINI
$(LIBNETDISSECT): $(LIBNETDISSECT_OBJ)
	@rm -f $@
	$(AR) cr $@ $(LIBNETDISSECT_OBJ) 
	$(RANLIB) $@
endif

datalinks.o: $(srcdir)/missing/datalinks.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/datalinks.c
dlnames.o: $(srcdir)/missing/dlnames.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/dlnames.c
getnameinfo.o: $(srcdir)/missing/getnameinfo.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/getnameinfo.c
getaddrinfo.o: $(srcdir)/missing/getaddrinfo.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/getaddrinfo.c
inet_pton.o: $(srcdir)/missing/inet_pton.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/inet_pton.c
inet_ntop.o: $(srcdir)/missing/inet_ntop.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/inet_ntop.c
inet_aton.o: $(srcdir)/missing/inet_aton.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/inet_aton.c
snprintf.o: $(srcdir)/missing/snprintf.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/snprintf.c
strlcat.o: $(srcdir)/missing/strlcat.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/strlcat.c
strlcpy.o: $(srcdir)/missing/strlcpy.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/strlcpy.c
strsep.o: $(srcdir)/missing/strsep.c
	$(CC) $(FULL_CFLAGS) -o $@ -c $(srcdir)/missing/strsep.c

version.o: version.c
	$(CC) $(FULL_CFLAGS) -c version.c

version.c: $(srcdir)/VERSION
	@rm -f $@
	if grep GIT ${srcdir}/VERSION >/dev/null; then \
		read ver <${srcdir}/VERSION; \
		echo $$ver | tr -d '\012'; \
		date +_%Y_%m_%d; \
	else \
		cat ${srcdir}/VERSION; \
	fi | sed -e 's/.*/const char version[] = "&";/' > $@

install: all
	[ -d $(DESTDIR)$(sbindir) ] || \
	    (mkdir -p $(DESTDIR)$(sbindir); chmod 755 $(DESTDIR)$(sbindir))
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(sbindir)/$(PROG)
	$(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(sbindir)/$(PROG).`cat ${srcdir}/VERSION`
	[ -d $(DESTDIR)$(mandir)/man1 ] || \
	    (mkdir -p $(DESTDIR)$(mandir)/man1; chmod 755 $(DESTDIR)$(mandir)/man1)
	$(INSTALL_DATA) $(PROG).1 $(DESTDIR)$(mandir)/man1/$(PROG).1

uninstall:
	rm -f $(DESTDIR)$(sbindir)/$(PROG)
	rm -f $(DESTDIR)$(mandir)/man1/$(PROG).1

lint: $(GENSRC)
	lint -hbxn $(SRC) | \
	    grep -v 'struct/union .* never defined' | \
	    grep -v 'possible pointer alignment problem'

clean:
	rm -f $(CLEANFILES) $(PROG)-`cat VERSION`.tar.gz

distclean:
	rm -f $(CLEANFILES) Makefile config.cache config.log config.status \
	    config.h gnuc.h os-proto.h stamp-h stamp-h.in $(PROG).1
	rm -rf autom4te.cache

check: tcpdump
	(cd tests && ./TESTrun.sh)

tags: $(TAGFILES)
	ctags -wtd $(TAGFILES)

TAGS: $(TAGFILES)
	etags $(TAGFILES)

releasetar:
	@cwd=`pwd` ; dir=`basename $$cwd` ; name=$(PROG)-`cat VERSION` ; \
	   mkdir $$name; \
	   tar cf - $(CSRC) $(HDR) $(LIBNETDISSECT_SRC) $(EXTRA_DIST) $(TEST_DIST) | (cd $$name; tar xf -); \
	   tar -c -z -f $$name.tar.gz $$name; \
	   rm -rf $$name

testlist:
	echo $(TEST_DIST)

depend: $(GENSRC)
	$(MKDEP) -c $(CC) -m $(DEPENDENCY_CFLAG) $(DEFS) $(INCLS) $(SRC)
