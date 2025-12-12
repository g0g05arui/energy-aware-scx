KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
PAHOLE ?= pahole
LLVM_OBJCOPY ?= $(shell \
	if command -v llvm-objcopy >/dev/null 2>&1; then command -v llvm-objcopy; \
	elif command -v llvm-objcopy-18 >/dev/null 2>&1; then command -v llvm-objcopy-18; \
	elif command -v llvm-objcopy-17 >/dev/null 2>&1; then command -v llvm-objcopy-17; \
	elif command -v llvm-objcopy-16 >/dev/null 2>&1; then command -v llvm-objcopy-16; \
	elif command -v llvm-objcopy-15 >/dev/null 2>&1; then command -v llvm-objcopy-15; \
	elif command -v llvm-objcopy-14 >/dev/null 2>&1; then command -v llvm-objcopy-14; \
	else command -v objcopy; fi)
export LLVM_OBJCOPY

obj-m := therm_kfunc.o
EXTRA_CFLAGS += -g

.PHONY: all btf clean

all: therm_kfunc.ko btf

therm_kfunc.ko:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

btf: therm_kfunc.ko
	@if command -v $(PAHOLE) >/dev/null 2>&1; then \
		echo "Embedding BTF into therm_kfunc.ko"; \
		LLVM_OBJCOPY="$(LLVM_OBJCOPY)" $(PAHOLE) -J $(PWD)/therm_kfunc.ko; \
	else \
		echo "WARNING: pahole not found; module BTF will be missing"; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
