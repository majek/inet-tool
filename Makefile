CLANG      ?= clang
KERNEL_DIR ?=

HOST_ARCH = $(shell uname -m)-linux-gnu
LIBC_INC_DIR = /usr/include/$(HOST_ARCH)

ifeq ($(KERNEL_DIR),)
# Build against system packages.
#
# On Debian:
#
#   $ apt install linux-libc-dev libbpf-dev
#
LINUX_INC_DIR  = /usr/include
LIBBPF_INC_DIR = /usr/include
LIBBPF_LIB_DIR = /usr/lib/$(HOST_ARCH)
else
# Build against kernel source tree.
#
# Prepare headers and build libbpf:
#
#   $ make headers_install && make -C tools/lib/bpf
#
LINUX_INC_DIR  = $(KERNEL_DIR)/usr/include
LIBBPF_INC_DIR = $(KERNEL_DIR)/tools/lib
LIBBPF_LIB_DIR = $(KERNEL_DIR)/tools/lib/bpf
endif

# make: by default build inet-tool
all: venv/.ok inet-tool

.PHONY: check_kernel
check_kernel:
ifeq ("$(shell grep BPF_INET_LOOKUP $(LINUX_INC_DIR)/linux/bpf.h)","")
	$(error KERNEL_DIR must point to kernel with INET_LOOKUP patches)
endif

##VERSION := $(shell git describe --tags --always --dirty="-dev")

# Let the ebpf program version be its source checksum.
EBPF_VERSION := $(shell cat ebpf/*.[ch]|sort|sha1sum |cut -c 1-8)

DEPS_H = \
	$(LINUX_INC_DIR)/linux/bpf.h \
	$(LIBBPF_INC_DIR)/bpf/bpf.h \
	$(LIBBPF_INC_DIR)/bpf/libbpf.h \
	$(LIBBPF_INC_DIR)/bpf/bpf_endian.h \
	$(LIBBPF_INC_DIR)/bpf/bpf_helpers.h

DEPS     = $(LIBBPF_LIB_DIR)/libbpf.a $(DEPS_H)
INCLUDES = -I$(LIBC_INC_DIR) -I$(LINUX_INC_DIR) -I$(LIBBPF_INC_DIR)

INET_TOOL_DEPS=src/*.[ch] $(DEPS) inet-ebpf.c Makefile ebpf/*shared*

inet-tool: $(INET_TOOL_DEPS)
	$(CLANG) -g -Wall -Wextra -O2 \
		$(EXTRA_CFLAGS) \
		$(INCLUDES) \
		src/tbpf.c \
		src/main.c \
		src/inet-commands.c \
		src/utils.c \
		inet-ebpf.c \
		src/inet-scm.c \
		$(LIBBPF_LIB_DIR)/libbpf.a \
		-D INET_PROGRAM_VERSION=\"inet_$(EBPF_VERSION)\" \
		-l elf \
		-o $@

$(DEPS): check_kernel

inet-ebpf.c: ebpf/*.[ch] tbpf-decode-elf.py $(DEPS_H) ebpf/*shared*
	$(CLANG) -Wall -Wextra -O2 --target=bpf -c \
		$(INCLUDES) \
		ebpf/inet-kern.c \
		-o - \
		| ./venv/bin/python3 tbpf-decode-elf.py /dev/stdin \
			inet_program \
		> $@

inet-tool-test: $(INET_TOOL_DEPS)
	rm -f inet-tool
	$(MAKE) inet-tool EXTRA_CFLAGS="--coverage -D CODE_COVERAGE=1"
	mv -f inet-tool inet-tool-test


# We need python3 virtualenv with pyelftools installed for the tbpf-decode-elf script
venv/.ok:
	virtualenv venv --python=python3
	./venv/bin/pip3 install pyelftools
	touch $@

# make format
.PHONY: format
format:
	clang-format -i src/*.[ch] ebpf/*.[ch]
	@grep -n "TODO" src/*.[ch] ebpf/*.[ch] || true

# make test
.PHONY: test
test: inet-tool-test
	@rm -rf *.gcda cov_html cov.info
	INETTOOLBIN="./inet-tool-test" \
		PYTHONPATH=. PYTHONIOENCODING=utf-8 python3 -m tests.runner tests
	@lcov -q --directory .  --gcov-tool ./tools/llvm-gcov.sh --capture --no-external --config-file .lcovrc -o cov.info 2> /dev/null
	@genhtml -q cov.info -o cov_html -t inet-tool --config-file .lcovrc
	@echo "[*] Coverage report:"
	@lcov -q --no-list-full-path --list cov.info --config-file .lcovrc
	@rm -rf *.gcda cov.info
	@echo "[*] Run:\n  xdg-open cov_html/src/index.html"

# make clean
.PHONY: clean
clean:
	rm -f inet-tool deps/* inet-ebpf.c
	rm -rf venv tests/__pycache__
	rm -r inet-tool-test *.gcno
	rm -rf *.gcda cov_html cov.info
