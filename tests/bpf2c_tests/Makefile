# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

CFLAG = -Wall -g -std=c++17 -fPIE -Wno-unknown-pragmas

CC = g++
INCLUDES = -I../../include -I../../packages/CatchOrg.Catch.2.8.0/lib/native/include -I../../external/ubpf/vm -I../../external/ebpf-verifier/external/ELFIO -I../../tools/bpf2c/ -I../../tests/libs/util

bpf2c_tests: bpf_code_generator.o raw_bpf.o btf_parser.o
	${CC} ${CFLAG} bpf_code_generator.o raw_bpf.o -o bpf2c_tests

bpf_code_generator.o: ../../tools/bpf2c/bpf_code_generator.cpp 
	${CC} ${CFLAG} ${INCLUDES} -c $<

raw_bpf.o: raw_bpf.cpp
	${CC} ${CFLAG} ${INCLUDES} -c $<

btf_parser.o: ../../tools/bpf2c/btf_parser.cpp
	${CC} ${CFLAG} ${INCLUDES} -c $<

clean:
	rm -f *.o bpf2c_tests *.data.* *.data
