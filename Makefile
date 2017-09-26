LPCAPDIR := "."
LD = /usr/bin/ld
CC = gcc
AR = ar
LN_S = ln -s
MKDEP = 
CCOPT =  -fpic
INCLS = -I${LPCAPDIR} 
DEFS = -DHAVE_CONFIG_H  -D_U_="__attribute__((unused))"
ADDLOBJS = 
ADDLARCHIVEOBJS = 
LIBS = 
CROSSFLAGS=
CFLAGS = -g -O2   ${CROSSFLAGS}
LDFLAGS =  ${CROSSFLAGS}
DYEXT = so
V_RPATH_OPT = -Wl,-rpath,
DEPENDENCY_CFLAG = 
PROG=libpcap
RMF = rm -f

# Standard CFLAGS
FULL_CFLAGS = $(CCOPT) $(INCLS) $(DEFS) $(CFLAGS)

capturet: src/capturet.c libpcap.a
	$(CC) $(FULL_CFLAGS) -I${LPCAPDIR} -L${LPCAPDIR} -o $@ $^ $(LIBS)

clean:
	${RMF} capturet
