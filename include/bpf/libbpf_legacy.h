// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#if __LIBBPF_CURRENT_VERSION_GEQ(0, 7)
#define __LIBBPF_MARK_DEPRECATED_0_7(X) X
#else
#define __LIBBPF_MARK_DEPRECATED_0_7(X)
#endif
#if __LIBBPF_CURRENT_VERSION_GEQ(0, 8)
#define __LIBBPF_MARK_DEPRECATED_0_8(X) X
#else
#define __LIBBPF_MARK_DEPRECATED_0_8(X)
#endif

LIBBPF_API LIBBPF_DEPRECATED_SINCE(
    0, 7, "track bpf_objects in application code instead") struct bpf_object* bpf_object__next(struct bpf_object* prev);
#define bpf_object__for_each_safe(pos, tmp)                                            \
    for ((pos) = bpf_object__next(NULL), (tmp) = bpf_object__next(pos); (pos) != NULL; \
         (pos) = (tmp), (tmp) = bpf_object__next(tmp))

LIBBPF_API LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_object__next_map() instead") struct bpf_map* bpf_map__next(
    const struct bpf_map* map, const struct bpf_object* obj);
LIBBPF_API LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_object__prev_map() instead") struct bpf_map* bpf_map__prev(
    const struct bpf_map* map, const struct bpf_object* obj);

LIBBPF_API
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_object__next_program() instead")
struct bpf_program*
bpf_program__next(struct bpf_program* prog, const struct bpf_object* obj);
LIBBPF_API
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_object__prev_program() instead")
struct bpf_program*
bpf_program__prev(struct bpf_program* prog, const struct bpf_object* obj);

/* returns program size in bytes */
LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_program__insn_cnt() instead")
LIBBPF_API size_t
bpf_program__size(const struct bpf_program* prog);

LIBBPF_DEPRECATED_SINCE(0, 7, "use bpf_object__open() and bpf_object__load() instead")
LIBBPF_API int
bpf_prog_load_deprecated(const char* file, enum bpf_prog_type type, struct bpf_object** pobj, int* prog_fd);

LIBBPF_DEPRECATED_SINCE(0, 8, "use bpf_xdp_attach() instead")
LIBBPF_API int
bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);
