# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

CFLAG = -Wall -g -std=c++17 -fPIE -Wno-unknown-pragmas

CC = g++
INCLUDES = -I../../include -I../../packages/CatchOrg.Catch.2.8.0/lib/native/include -I../../external/ubpf/vm -I../../external/ebpf-verifier/external/ELFIO -I../../tools/bpf2c/ -I../../tests/libs/util

bpf2c_tests: ../../tools/bpf2c/bpf_code_generator.cpp raw_bpf.cpp ../../tools/bpf2c/btf_parser.cpp
	${CC} ${CFLAG} ${INCLUDES} $^ -o $@

clean:
	rm -f *.o bpf2c_tests *.data.* *.data
