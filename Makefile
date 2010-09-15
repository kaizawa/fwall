#
# Copyright (C) 2005-2010 Kazuyoshi Aizawa. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
CC = gcc
PRODUCTS = fwall fwalladm
CCFLAGS = -g
CCKFLAGS = ${CCFLAGS} -D_KERNEL -c -m64
CCADMFLAGS = ${CCFLAGS} -lnsl
LDFLAGS = -dn -r 
AUTOPUSH = /etc/autopush
ECHO = /bin/echo
CP = /bin/cp
RM = /bin/rm
LD = ld
RM = /bin/rm
CAT = /bin/cat
AWK = /bin/awk

all: $(PRODUCTS)

clean:
	${RM} -f fwall fwall.o fwall_rule.o fwalladm

fwall: fwall.o fwall_rule.o
	$(LD) ${LDFLAGS} fwall.o fwall_rule.o -o fwall 

fwall.o: fwall.c fwall.h
	$(CC) ${CCKFLAGS} fwall.c  

fwall_rule.o: fwall_rule.c fwall.h
	$(CC) ${CCKFLAGS} fwall_rule.c

fwalladm: fwalladm.c fwall.h
	$(CC) ${CCADMFLAGS} fwalladm.c -o fwalladm 

install:
	-$(CP) fwall /kernel/strmod/sparcv9/fwall
	-$(CP) fwalladm /usr/local/bin/fwalladm
	-$(CP) fwallcntl /usr/local/bin/fwallcntl

uninstall:
	-/usr/local/bin/fwallcntl stop
	-$(RM) /kernel/strmod/sparcv9/fwall
	-$(RM) /usr/local/bin/fwalladm
	-$(RM) /usr/local/bin/fwallcntl
