
#include "bpf_endian.h"
#include "bpf_helpers.h"

struct val
{
    uint32_t current_pid;
    uint64_t start_key;
} val;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct val);
    __uint(max_entries, 1);
} process_start_key_map SEC(".maps");

SEC("sockops")
int
func(bpf_sock_ops_t* ctx)
{
    const uint16_t ebpf_test_port = 0x3bbf; // Host byte order.
    struct val v = {.current_pid = 0, .start_key = 0};

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    v.start_key = bpf_get_current_process_start_key();
    v.current_pid = pid_tgid >> 32;
    uint32_t key = 0;
    bpf_map_update_elem(&process_start_key_map, &key, &v, 0);

    return 0;
}