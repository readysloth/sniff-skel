#include "vmlinux.h"
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <skel-def.bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 128);
  __type(key, u32);
  __type(value, u32);
} OUTPUT SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, output_info_t);
} OUTPUT_INFO SEC(".maps");


#define TRACE_INIT(NAME) \
    output_info_t *info = create_output_info(STR(NAME)); \
    if (!info) { DEBUG_TRACE("create_output_info failed"); return 0; }

#define TRACE_END() \
    int __err = 0; \
    if (__err = bpf_perf_event_output(ctx, &OUTPUT, BPF_F_CURRENT_CPU, info, sizeof(output_info_t))) {\
        DEBUG_TRACE("bpf_perf_event_output failed with %i", __err); \
    }

#define TRACE(NAME, ...) \
    int BPF_KPROBE(NAME, ## __VA_ARGS__)

#define TRACE_RET(NAME, ...) \
    int BPF_KRETPROBE(NAME, ## __VA_ARGS__)


static size_t write_small_str_to_heap(heap_t *heap, small_str str) {
    if (heap->taken > HEAP_SIZE - SMALL_STR_SIZE){
        DEBUG_TRACE("free heap space is less than SMALL_STR_SIZE");
        return 0;
    }
    strncpy(FREE_HEAP_PTR(heap), str, SMALL_STR_SIZE);

    size_t written_bytes = min(SMALL_BUF_SIZE, strlen(str) + 1);
    heap->taken += written_bytes;
    return written_bytes;
}

static size_t read_user_str_to_heap(heap_t *heap, const char *str) {
    const unsigned int space_per_record = 64;
    if (heap->taken > HEAP_SIZE - space_per_record){
        DEBUG_TRACE("free heap space is less than space_per_record");
        return 0;
    }

    int ret = bpf_probe_read_user_str(
        FREE_HEAP_PTR(heap),
        space_per_record,
        str
    );
    if (ret < 0){
        write_small_str_to_heap(heap, "%READ_ERROR%");
        return sizeof("%READ_ERROR%");
    }
    heap->taken += ret;
    return (size_t)ret;
}

static size_t read_kernel_str_to_heap(heap_t *heap, const char *str) {
    const unsigned int space_per_record = 64;
    if (heap->taken > HEAP_SIZE - space_per_record){
        DEBUG_TRACE("free heap space is less than space_per_record");
        return 0;
    }

    int ret = bpf_probe_read_kernel_str(
        FREE_HEAP_PTR(heap),
        space_per_record,
        str
    );
    if (ret < 0){
        write_small_str_to_heap(heap, "%READ_ERROR%");
        return sizeof("%READ_ERROR%");
    }
    heap->taken += ret;
    return (size_t)ret;
}

static void convert_heap_delimiters(heap_t *heap){
    const unsigned int border = MAX_BUF_SIZE;
    for (unsigned int i = 0; i < MAX_BUF_SIZE; i++){
        if (heap->buffer[i] == '\0' && i < heap->taken - 1){
            heap->buffer[i] = ' ';
        }
    }
}

static output_info_t* create_output_info(small_str trace_fname){
    int zero = 0;
    output_info_t *output_info = bpf_map_lookup_elem(&OUTPUT_INFO, &zero);
    if (!output_info){
        DEBUG_TRACE("*output_info not found in OUTPUT_INFO array");
        return output_info;
    }

    strncpy(output_info->gen_info.fname, trace_fname, SMALL_STR_SIZE);
    bpf_get_current_comm(
        output_info->gen_info.procname,
        sizeof(output_info->gen_info.procname)
    );

    output_info->gen_info.pid = bpf_get_current_pid_tgid() >> 32;
    return output_info;
}


SEC("uprobe")
TRACE(uprb /* , ARGS */)
{
  DEBUG_TRACE("U START");
  TRACE_INIT(uprb);
  DEBUG_TRACE("U BODY");
  TRACE_END();
  DEBUG_TRACE("U END");
  return 0;
}

SEC("uretprobe/:uprb")
TRACE(uretprb /* , ARGS */)
{
  DEBUG_TRACE("URET START");
  TRACE_INIT(uretprb);
  DEBUG_TRACE("URET BODY");
  TRACE_END();
  DEBUG_TRACE("URET END");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
