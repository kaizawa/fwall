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
LD = /usr/ucb/ld
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
