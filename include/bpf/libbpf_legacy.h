// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @name Link-related functions
 * @{
 */

/**
 * @brief Attach an XDP program to a given interface.
 *
 * @param[in] ifindex The interface index to attach to, or -1 to detach.
 * @param[in] fd File descriptor of program to attach.
 * @param[in] flags Flags. Use XDP_FLAGS_REPLACE to replace any program previously attached to
 *                  the specified interface index.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @deprecated Use bpf_xdp_attach() instead.
 *
 * @sa bpf_program__attach_xdp
 * @sa bpf_xdp_attach
 * @sa bpf_xdp_detach
 */
__declspec(deprecated("Use bpf_xdp_attach() instead.")) int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);

/** @} */

/**
 * @name Map-related functions
 * @{
 */

/**
 * @brief Get the next map for a given eBPF object.
 *
 * @param[in] map Previous map.
 * @param[in] obj Object with maps.
 *
 * @returns Next map, or NULL if none.
 *
 * @deprecated Use bpf_object__next_map() instead.
 *
 * @sa bpf_map__prev
 */
__declspec(deprecated("Use bpf_object__next_map() instead.")) struct bpf_map* bpf_map__next(
    const struct bpf_map* map, const struct bpf_object* obj);

/**
 * @brief Get the previous map for a given eBPF object.
 *
 * @param[in] map Next map.
 * @param[in] obj Object with maps.
 *
 * @returns Previous map, or NULL if none.
 *
 * @deprecated Use bpf_object__prev_map() instead.
 *
 * @sa bpf_map__next
 */
__declspec(deprecated("Use bpf_object__prev_map() instead.")) struct bpf_map* bpf_map__prev(
    const struct bpf_map* map, const struct bpf_object* obj);

/** @} */

/**
 * @name Object-related functions
 * @{
 */

struct bpf_object_load_attr
{
    struct bpf_object* obj;
    int log_level;
    const char* target_btf_path;
};

/**
 * @brief Load all the programs in a given object.
 *
 * @param[in] attr Structure with load attributes.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @deprecated Use bpf_object__load() instead.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception ENOMEM Out of memory.
 *
 * @sa bpf_object__open
 * @sa bpf_object__load_xattr
 * @sa bpf_prog_load
 */
__declspec(deprecated("Use bpf_object__load() instead.")) int bpf_object__load_xattr(struct bpf_object_load_attr* attr);

/**
 * @brief Get the next eBPF object opened by the calling process.
 *
 * @param[in] prev Previous object, or NULL to get the first object.
 *
 * @returns Next object, or NULL if none.
 *
 * @deprecated Track bpf_objects in application code instead.
 */
__declspec(deprecated("Track bpf_objects in application code instead.")) struct bpf_object* bpf_object__next(
    struct bpf_object* prev);

#define bpf_object__for_each_safe(pos, tmp)                                            \
    for ((pos) = bpf_object__next(NULL), (tmp) = bpf_object__next(pos); (pos) != NULL; \
         (pos) = (tmp), (tmp) = bpf_object__next(tmp))

/**
 * @brief Unload all the programs in a given object.
 *
 * @param[in] obj Object with programs to be unloaded.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @deprecated Use bpf_object__close() instead.
 *
 * @sa bpf_object__load
 * @sa bpf_object__load_xattr
 * @sa bpf_prog_load
 */
__declspec(deprecated("Use bpf_object__close() instead.")) int bpf_object__unload(struct bpf_object* obj);

/** @} */

/**
 * @name Program-related functions
 * @{
 */

/**
 * @brief Load (but do not attach) eBPF maps and programs from an ELF file.
 *
 * @param[in] file Path name to an ELF file.
 * @param[in] type Program type to use for loading eBPF programs.  If BPF_PROG_TYPE_UNKNOWN,
 * the program type is derived from the section prefix in the ELF file.
 * @param[out] pobj Pointer to where to store the eBPF object loaded. The caller
 * is expected to call bpf_object__close() to free the object.
 * @param[out] prog_fd Returns a file descriptor for the first program.
 * The caller should not call _close() on the fd, but should instead use
 * bpf_object__close() on the object returned.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @deprecated Use bpf_object__open() and bpf_object__load() instead.
 *
 * @exception EACCES The program failed verification.
 * @exception EINVAL One or more parameters are incorrect.
 * @exception ENOMEM Out of memory.
 *
 * @sa bpf_load_program
 * @sa bpf_load_program_xattr
 * @sa bpf_object__close
 * @sa bpf_program__attach
 */
__declspec(deprecated("Use bpf_object__open() and bpf_object__load() instead.")) int bpf_prog_load_deprecated(
    const char* file, enum bpf_prog_type type, struct bpf_object** pobj, int* prog_fd);

/**
 * @brief Get the next program for a given eBPF object.
 *
 * @param[in] prog Previous program, or NULL to get the first program.
 * @param[in] obj Object with programs.
 *
 * @returns Next program, or NULL if none.
 *
 * @deprecated Use bpf_object__next_program() instead.
 *
 * @sa bpf_program__prev
 */
__declspec(deprecated("Use bpf_object__next_program() instead.")) struct bpf_program* bpf_program__next(
    struct bpf_program* prog, const struct bpf_object* obj);

/**
 * @brief Get the previous eBPF program for a given eBPF object.
 *
 * @param[in] prog Next program.
 * @param[in] obj Object with programs.
 *
 * @returns Previous eBPF program, or NULL if none.
 *
 * @deprecated Use bpf_object__prev_program() instead.
 *
 * @sa bpf_program__next
 */
__declspec(deprecated("Use bpf_object__prev_program() instead.")) struct bpf_program* bpf_program__prev(
    struct bpf_program* prog, const struct bpf_object* obj);

/**
 * @brief Get the eBPF program size in bytes.
 *
 * @param[in] prog Program.
 *
 * @returns Program size in bytes.
 *
 * @deprecated Use bpf_program__insn_cnt() instead.
 */
__declspec(deprecated("Use bpf_program__insn_cnt() instead.")) size_t bpf_program__size(const struct bpf_program* prog);

/** @} */
