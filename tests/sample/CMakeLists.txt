# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_subdirectory("ext")
add_subdirectory("unsafe")

# build eBPF Samples.
build_bpf_samples(FALSE)