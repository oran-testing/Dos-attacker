# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.

bin_PROGRAMS		=	cufh-attacker
cufh_attacker_SOURCES	=	main.c \
						cpus.c \
						dpdk.c \
						pcap.c \
						utils.c

cufh_attacker_CFLAGS	:=	$(CFLAGS) -I/usr/include/dpdk -march=native -I$(includedir)
cufh_attacker_LDFLAGS	:=	$(LDFLAGS) -L$(libdir) -pthread -lnuma -lm -ldl \
						-Wl,--whole-archive -Wl,--start-group \
						-ldpdk \
						-Wl,--end-group -Wl,--no-whole-archive
