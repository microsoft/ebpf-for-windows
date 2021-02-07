#pragma clang section text="xdp_prog"

typedef int (*bpf_helper)(int a, int b, int c, int d);

#define ebpf_map_lookup_elem ((bpf_helper)0)
#define ebpf_map_update_elem ((bpf_helper)1)
#define ebpf_map_delete_elem ((bpf_helper)2)
#define ebpf_get_tick_count ((bpf_helper)3)

typedef struct xdp_md 
{
    unsigned char* data;
    unsigned char* data_end;
    unsigned char* data_meta;
} xdp_md;

int func(xdp_md * ctx)
{
    return ebpf_get_tick_count(ctx, 0, 0, 0);
}
	
