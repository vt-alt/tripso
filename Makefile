# SPDX-License-Identifier: GPL-2.0
#
# Makefile for TRIPSO module.
#

KVER	?= $(shell uname -r)
KDIR	?= /lib/modules/$(KVER)/build/
DEPMOD	= /sbin/depmod -a
CC	?= gcc
CFLAGS	?= -O2 -g
XFLAGS	?= $(shell pkg-config xtables --cflags 2>/dev/null)
XDIR	?= $(shell pkg-config --variable xtlibdir xtables)
VERSION	= $(shell git -C $M describe --dirty)
VOPT	= '-DVERSION="$(VERSION)"'
obj-m	= xt_TRIPSO.o
CFLAGS_xt_TRIPSO.o = -DDEBUG $(VOPT)

all: xt_TRIPSO.ko libxt_TRIPSO.so

xt_TRIPSO.ko: xt_TRIPSO.c xt_TRIPSO.h
	make -C $(KDIR) M=$(CURDIR) modules CONFIG_DEBUG_INFO=y

install: install-mod install-lib

install-mod: xt_TRIPSO.ko
	make -C $(KDIR) M=$(CURDIR) modules_install INSTALL_MOD_PATH=$(DESTDIR)

install-lib: libxt_TRIPSO.so
	install -D $< $(DESTDIR)$(shell pkg-config --variable xtlibdir xtables)/$<

%.so: %_sh.o
	gcc -shared -o $@ $< $(shell pkg-config xtables --libs)

%_sh.o: libxt_TRIPSO.c xt_TRIPSO.h
	gcc -Wall -Wunused -fPIC $(XFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	-make -C $(KDIR) M=$(CURDIR) clean
	-rm -f *.so *.o modules.order

.PHONY: clean all install install-mod install-lib
