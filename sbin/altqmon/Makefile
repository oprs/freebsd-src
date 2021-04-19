# $FreeBSD$

.include <src.opts.mk>

# pf_ruleset.c is shared between kernel and pfctl
.PATH: ${SRCTOP}/sys/netpfil/pf

PACKAGE=altqmon
#CONFS=	pf.os
PROG=	altqmon
MAN=
SRCS = altqmon.c

WARNS?=	2
CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -DENABLE_ALTQ -I${.CURDIR}

# Need to use "WITH_" prefix to not conflict with the l/y INET/INET6 keywords
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DWITH_INET6
.endif
.if ${MK_INET_SUPPORT} != "no"
CFLAGS+= -DWITH_INET
.endif

YFLAGS=

LIBADD=	m md

#HAS_TESTS=
#SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
