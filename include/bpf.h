// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifdef __doxygen

/**
 * @name Link-related functions
 * @{
 */

/**
 * @brief Detach a link.
 *
 * @param[in] link_fd File descriptor of link to detach.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception EBADF The file descriptor was not found.
 *
 * @sa bpf_link__destroy
 * @sa bpf_link__disconnect
 */
int
bpf_link_detach(int link_fd);

/**
 * @brief Get a file descriptor referring to a link
 * with a given ID.
 *
 * @param[in] id ID of link to find.
 *
 * @returns A new file descriptor that refers to the link.  A negative
 * value indicates an error occurred and errno was set.
 *
 * @exception ENOENT No link with the specified ID was found.
 */
int
bpf_link_get_fd_by_id(__u32 id);

/**
 * @brief Look for the next link ID greater than a given ID.
 *
 * @param[in] start_id ID to look for an ID after. The start_id need not exist.
 * @param[out] next_id Pointer to where to write the next ID.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception ENOENT No more IDs found.
 */
int
bpf_link_get_next_id(__u32 start_id, __u32* next_id);

/** @} */

/**
 * @name Map-related functions
 * @{
 */

/**
 * @brief Create a new map.
 *
 * @param[in] map_type Type of map to create.
 * @param[in] key_size Size in bytes of keys.
 * @param[in] value_size Size in bytes of values.
 * @param[in] max_entries Maximum number of entries in the map.
 * @param[in] map_flags Flags (currently 0).
 *
 * @returns A new file descriptor that refers to the map.  A negative
 * value indicates an error occurred and errno was set.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception ENOMEM Out of memory.
 */
int
bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, __u32 map_flags);

/**
 * @brief Look up and delete an element by key in a specified map.
 *
 * @param[in] fd File descriptor of map to update.
 * @param[in] key Pointer to key to look up.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception EBADF The file descriptor was not found.
 * @exception ENOMEM Out of memory.
 */
int
bpf_map_delete_elem(int fd, const void* key);

/**
 * @brief Get a file descriptor referring to a map
 * with a given ID.
 *
 * @param[in] id ID of map to find.
 *
 * @returns A new file descriptor that refers to the map.  A negative
 * value indicates an error occurred and errno was set.
 *
 * @exception ENOENT No map with the specified ID was found.
 */
int
bpf_map_get_fd_by_id(__u32 id);

/**
 * @brief Look for the next map ID greater than a given ID.
 *
 * @param[in] start_id ID to look for an ID after. The start_id need not exist.
 * @param[out] next_id Pointer to where to write the next ID.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception ENOENT No more IDs found.
 */
int
bpf_map_get_next_id(__u32 start_id, __u32* next_id);

/**
 * @brief Look up an element by key in a map and get the next key.
 * If the specific key is not found, the first key in the map is
 * passed back.
 *
 * @param[in] fd File descriptor of map.
 * @param[in] key Pointer to key to look up.
 * @param[out] next_key Pointer to memory in which to write the
 * next key.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception EBADF The file descriptor was not found.
 * @exception ENOMEM Out of memory.
 */
int
bpf_map_get_next_key(int fd, const void* key, void* next_key);

/**
 * @brief Look up an element by key in a specified map and
 * return its value.
 *
 * @param[in] fd File descriptor of map.
 * @param[in] key Pointer to key to look up.
 * @param[out] value Pointer to memory in which to write the
 * value.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception EBADF The file descriptor was not found.
 * @exception ENOMEM Out of memory.
 */
int
bpf_map_lookup_elem(int fd, const void* key, void* value);

/**
 * @brief Create or update an element (key/value pair) in a
 * specified map.
 *
 * @param[in] fd File descriptor of map.
 * @param[in] key Pointer to key.
 * @param[in] value Pointer to value.
 * @param[in] flags Flags (currently 0).
 *
 * @exception EINVAL An invalid argument was provided.
 * @exception EBADF The file descriptor was not found.
 * @exception ENOMEM Out of memory.
 */
int
bpf_map_update_elem(int fd, const void* key, const void* value, __u64 flags);

/** @} */

/**
 * @name Object-related functions
 * @{
 */

/**
 * @brief Obtain information about the eBPF object referred to by bpf_fd.
 * This function populates up to info_len bytes of info, which will
 * be in one of the following formats depending on the eBPF object type of
 * bpf_fd:
 *
 * * struct bpf_link_info
 * * struct bpf_map_info
 * * struct bpf_prog_info
 *
 *
 * @param[in] bpf_fd File descriptor referring to an eBPF object.
 * @param[out] info Pointer to memory in which to write the info obtained.
 * @param[in,out] info_len On input, contains the maximum number of bytes to
 * write into the info.  On output, contains the actual number of bytes written.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 */
int
bpf_obj_get_info_by_fd(int bpf_fd, void* info, __u32* info_len);

/** @} */

/**
 * @name Program-related functions
 * @{
 */

/**
 * @brief Get a file descriptor referring to a program
 * with a given ID.
 *
 * @param[in] id ID of program to find.
 *
 * @returns A new file descriptor that refers to the program.  A negative
 * value indicates an error occurred and errno was set.
 *
 * @exception ENOENT No program with the specified ID was found.
 */
int
bpf_prog_get_fd_by_id(__u32 id);

/**
 * @brief Look for the next program ID greater than a given ID.
 *
 * @param[in] start_id ID to look for an ID after. The start_id need not exist.
 * @param[out] next_id Pointer to where to write the next ID.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occured, and errno was set.
 *
 * @exception ENOENT No more IDs found.
 */
int
bpf_prog_get_next_id(__u32 start_id, __u32* next_id);

/** @} */

#else
#pragma warning(push)
#include "../external/libbpf/src/bpf.h"
#pragma warning(pop)
#endif
