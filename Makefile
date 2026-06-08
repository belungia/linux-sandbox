#   make                              # модуль + userspace-утилиты
#   make KVER=6.14.0-37-generic       # явно под целевое ядро сдачи
#   make tools                        # только userspace
#   make clean

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

obj-m += sandbox.o
sandbox-y := src/sandbox_main.o \
             src/ftrace_hook.o \
             src/registry.o \
             src/shadow.o \
             src/hooks.o \
             src/procfs.o

ccflags-y += -I$(src)/src -Wall

all: module tools

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools: tools/sandbox_run

tools/sandbox_run: tools/sandbox_run.c
	$(CC) -O2 -Wall -o $@ $<

clean:
	-$(MAKE) -C $(KDIR) M=$(PWD) clean
	-rm -f tools/sandbox_run

.PHONY: all module tools clean
