
inet-tool
---------

The tool to manage SK_LOOKUP program.

Dependencies:

    apt install \
        build-essential \
        clang \
        clang-format \
        lcov \
        libc6-dev-i386 \
        libz-dev \
        python3-virtualenv \
        virtualenv

Clang is needed to compile C into the eBPF program.

First, you need to run experimental kernel with SK_LOOKUP
patches. For example:

    cd /tmp
    git clone https://github.com/jsitnicki/linux.git --branch bpf-inet-lookup --depth 1

Then you can build the `inet-tool`:

    (cd /tmp/linux && make headers_install && make -C tools/lib/bpf)
    make KERNEL_DIR=/tmp/linux

Tu run tests (requires root):

    sudo make test

