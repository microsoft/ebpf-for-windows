// Copyright (c) eBPF for Windows contributors
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
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -EBADF The file descriptor was not found.
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
 * @returns A new file descriptor that refers to the link.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @retval -ENOENT No link with the specified ID was found.
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
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -ENOENT No more IDs found.
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
 * @param[in] map_type Type of outer map to create.
 * @param[in] map_name Optionally, the name to use for the map.
 * @param[in] key_size Size in bytes of keys.
 * @param[in] value_size Size in bytes of values.
 * @param[in] max_entries Maximum number of entries in the map.
 * @param[in] opts Structure of options using which a map gets created.
 *
 * @returns A new file descriptor that refers to the map.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @retval -EINVAL An invalid argument was provided.
 * @retval -ENOMEM Out of memory.
 */
int
bpf_map_create(
    enum bpf_map_type map_type,
    const char* map_name,
    __u32 key_size,
    __u32 value_size,
    __u32 max_entries,
    const struct bpf_map_create_opts* opts);

/**
 * @brief Look up and delete an element by key in a specified map.
 *
 * @param[in] fd File descriptor of map to update.
 * @param[in] key Pointer to key to look up.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -EINVAL An invalid argument was provided.
 * @retval -EBADF The file descriptor was not found.
 * @retval -ENOMEM Out of memory.
 */
int
bpf_map_delete_elem(int fd, const void* key);

/**
 * @brief Get a file descriptor referring to a map
 * with a given ID.
 *
 * @param[in] id ID of map to find.
 *
 * @returns A new file descriptor that refers to the map.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @retval -ENOENT No map with the specified ID was found.
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
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -ENOENT No more IDs found.
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
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -EINVAL An invalid argument was provided.
 * @retval -EBADF The file descriptor was not found.
 * @retval -ENOMEM Out of memory.
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
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -EINVAL An invalid argument was provided.
 * @retval -EBADF The file descriptor was not found.
 * @retval -ENOMEM Out of memory.
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
 * @retval 0 The operation was successful.
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -EINVAL An invalid argument was provided.
 * @retval -EBADF The file descriptor was not found.
 * @retval -ENOMEM Out of memory.
 */
int
bpf_map_update_elem(int fd, const void* key, const void* value, __u64 flags);

/**
 * @brief **bpf_map_lookup_batch()** allows for batch lookup of BPF map elements.
 *
 * The parameter *in_batch* is the address of the first element in the batch to read. *out_batch* is an output parameter
 * that should be passed as *in_batch* to subsequent calls to **bpf_map_lookup_batch()**. NULL can be passed for
 * *in_batch* to indicate that the batched lookup starts from the beginning of the map. Both *in_batch* and *out_batch*
 * must point to memory large enough to hold a single key, except for maps of type **BPF_MAP_TYPE_{HASH, PERCPU_HASH,
 * LRU_HASH, LRU_PERCPU_HASH}**, for which the memory size must be atleast 4 bytes wide regardless of key size.
 *
 * The *keys* and *values* are output parameters which must point to memory large enough to hold *count* items based on
 * the key and value size of the map *map_fd*. The *keys* buffer must be of *key_size* * *count*. The *values* buffer
 * must be of *value_size* * *count*.
 *
 * @param[in] fd BPF map file descriptor.
 * @param[in] in_batch address of the first element in batch to read, can pass NULL to indicate that the batched lookup
 * starts from the beginning of the map.
 * @param[out] out_batch output parameter that should be passed to next call as *in_batch*.
 * @param[out] keys pointer to an array large enough for *count* keys.
 * @param[out] values pointer to an array large enough for *count* values. For per-CPU maps, the size of the array
 * should be at least count * value_size * number of logical CPUs. In case of per-CPU maps, the value_size is rounded up
 * to the nearest multiple of 8 bytes.
 * @param[in, out] count input and output parameter; on input it's the number of elements in the map to read in batch;
 * on output it's the number of elements that were successfully read.
 * @param[in] opts options for configuring the way the batch lookup works.
 *
 * @retval 0 The operation was successful.
 * @retval EINVAL An invalid argument was provided.
 * @retval ENOENT No more entries found, or the key was not found.
 */
int
bpf_map_lookup_batch(
    int fd,
    void* in_batch,
    void* out_batch,
    void* keys,
    void* values,
    __u32* count,
    const struct bpf_map_batch_opts* opts);

/**
 * @brief **bpf_map_lookup_and_delete_batch()** allows for batch lookup and deletion of BPF map elements where each
 * element is deleted after being retrieved.
 *
 * @param[in] fd BPF map file descriptor.
 * @param[in] in_batch address of the first element in batch to read, can pass NULL to get address of the first element
 * in *out_batch*. If not NULL, must be large enough to hold a key. For **BPF_MAP_TYPE_{HASH, PERCPU_HASH, LRU_HASH,
 * LRU_PERCPU_HASH}**, the memory size must be at least 4 bytes wide regardless of key size.
 * @param[out] out_batch output parameter that should be passed to next call as *in_batch*.
 * @param[out] keys pointer to an array of *count* keys.
 * @param[out] values pointer to an array of *count* values.For per-CPU maps, the size of the array should be at least
 * count * value_size * number of logical CPUs. In case of per-CPU maps, the value_size is rounded up to the
 * nearest multiple of 8 bytes.
 * @param[in, out] count input and output parameter; on input it's the number of elements in the map to read and
 * delete in batch; on output it represents the number of elements that were successfully read and deleted.
 * @param opts options for configuring the way the batch lookup and delete works.
 *
 * @retval 0 The operation was successful.
 * @retval EINVAL An invalid argument was provided.
 * @retval ENOENT No more entries found, or the key-value pair was not found.
 */
int
bpf_map_lookup_and_delete_batch(
    int fd,
    void* in_batch,
    void* out_batch,
    void* keys,
    void* values,
    __u32* count,
    const struct bpf_map_batch_opts* opts);

/**
 * @brief **bpf_map_update_batch()** updates multiple elements in a map by specifying keys and their corresponding
 * values.
 *
 * The *keys* and *values* parameters must point to memory large enough to hold *count* items based on the key and value
 * size of the map.
 *
 * The *opts* parameter can be used to control how *bpf_map_update_batch()* should handle keys that either do or do not
 * already exist in the map. In particular the *flags* parameter of *bpf_map_batch_opts* can be one of the following:
 *
 * Note that *count* is an input and output parameter, where on output it represents how many elements were successfully
 * updated.
 *
 * **BPF_ANY**
 *    Create new elements or update existing.
 *
 * **BPF_NOEXIST**
 *    Create new elements only if they do not exist.
 *
 * **BPF_EXIST**
 *    Update existing elements.
 *
 * @param[in] fd BPF map file descriptor.
 * @param[in] keys pointer to an array of *count* keys.
 * @param[in] values pointer to an array of *count* values. For per-CPU maps, the size of the array should be at least
 * count * value_size * number of logical CPUs. In case of per-CPU maps, the value_size is rounded up to the nearest
 * multiple of 8 bytes.
 * @param[in, out] count input and output parameter; on input it's the number of elements in the map to update in batch;
 * **count** represents the number of updated elements if the output **count** value is not equal to the input **count**
 * value.
 * @param[in] opts options for configuring the way the batch update works.
 *
 * @retval 0 The operation was successful.
 * @retval EINVAL An invalid argument was provided.
 * @retval ENOMEM Out of memory.
 */
int
bpf_map_update_batch(int fd, const void* keys, const void* values, __u32* count, const struct bpf_map_batch_opts* opts);

/**
 * @brief **bpf_map_delete_batch()** allows for batch deletion of multiple elements in a BPF map.
 *
 * @param[in] fd BPF map file descriptor.
 * @param[in] keys pointer to an array of *count* keys.
 * @param[in, out] count input and output parameter; on input **count** represents the number of  elements in the map to
 * delete in batch.
 * @param[in] opts options for configuring the way the batch deletion works.
 *
 * @retval 0 The operation was successful.
 * @retval EINVAL An invalid argument was provided.
 * @retval ENOENT The key was not found.
 */
int
bpf_map_delete_batch(int fd, const void* keys, __u32* count, const struct bpf_map_batch_opts* opts);

/** @} */

/**
 * @name Object-related functions
 * @{
 */

/**
 * @brief Get a file descriptor for a pinned object by pin path.
 * @param[in] pathname Pin path for the object.
 *
 * @return A new file descriptor for the pinned object.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 */
int
bpf_obj_get(const char* pathname);

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
 * @param[in, out] info_len On input, contains the maximum number of bytes to
 * write into the info.  On output, contains the actual number of bytes written.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occurred, and errno was set.
 * @retval -EFAULT A pointer passed in the input info was invalid.
 */
int
bpf_obj_get_info_by_fd(int bpf_fd, void* info, __u32* info_len);

/**
 * @brief Pin an eBPF program or map referred to by fd to the
 * provided pathname.
 *
 * @param[in] fd File descriptor referring to the program or map to pin.
 * @param[in] pathname Path name to pin the object to.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occurred, and errno was set.
 */
int
bpf_obj_pin(int fd, const char* pathname);

/** @} */

/**
 * @name Program-related functions
 * @{
 */

/**
 * @brief Bind a map to a program so that it holds a reference on the map.
 *
 * @param[in] prog_fd File descriptor of program to bind map to.
 * @param[in] map_fd File descriptor of map to bind.
 * @param[in] opts Optional set of options affecting the bind operation.
 *
 * @retval 0 The operation was successful.
 * @retval <0 An error occurred, and errno was set.
 */
int
bpf_prog_bind_map(int prog_fd, int map_fd, const struct bpf_prog_bind_opts* opts);

/**
 * @brief Get a file descriptor referring to a program
 * with a given ID.
 *
 * @param[in] id ID of program to find.
 *
 * @returns A new file descriptor that refers to the program.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @retval -ENOENT No program with the specified ID was found.
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
 * @retval <0 An error occurred, and errno was set.
 *
 * @retval -ENOENT No more IDs found.
 */
int
bpf_prog_get_next_id(__u32 start_id, __u32* next_id);

/**
 * @brief Load (but do not attach) an eBPF programs.
 *
 * @param[in] prog_type Program type to use for loading eBPF programs.
 * @param[in] prog_name Program name.
 * @param[in] license License string (unused).
 * @param[in] insns Array of eBPF instructions.
 * @param[in] insn_cnt Count of instructions in the array.
 * @param[in] opts Additional options, or NULL to use default options.
 *
 * @returns A new file descriptor that refers to the program.
 * The caller should call _close() on the fd to close this when done.
 * A negative value indicates an error occurred and errno was set.
 *
 * @retval -EACCES The program failed verification.
 * @retval -EINVAL One or more parameters are incorrect.
 * @retval -ENOMEM Out of memory.
 *
 * @sa bpf_load_program
 * @sa bpf_load_program_xattr
 * @sa bpf_object__close
 * @sa bpf_program__attach
 */
int
bpf_prog_load(
    enum bpf_prog_type prog_type,
    const char* prog_name,
    const char* license,
    const struct bpf_insn* insns,
    size_t insn_cnt,
    const struct bpf_prog_load_opts* opts);

/** @} */

#else
#pragma warning(push)
#include "bpf_legacy.h"
#include "libbpf/src/bpf.h"
#pragma warning(pop)
#endif
