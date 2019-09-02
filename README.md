
inet-tool
---------

The tool to manage INET_LOOKUP program.

Dependencies:

    apt install python3-virtualenv build-essential clang clang-format lcov

Clang is needed to compile C into the eBPF program.

First, you need to run experimental kernel with INET_LOOKUP
patches. For example:

    cd /tmp
    git clone https://github.com/jsitnicki/linux.git --branch bpf-inet-lookup --depth 1000

Then you can build the `inet-tool`:

    make KERNEL_DIR=/tmp/linux

To build:

    make

Tu run tests (requires root):

    sudo make test

