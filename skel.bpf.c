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

static char* to_hex(uint8_t byte){
    static char byte_vals_str[] = "00" "\0" "01" "\0" "02" "\0" "03" "\0" "04" "\0" "05" "\0" "06" "\0" "07" "\0" "08" "\0" "09" "\0" "0A" "\0" "0B" "\0" "0C" "\0" "0D" "\0" "0E" "\0" "0F" "\0" "10" "\0" "11" "\0" "12" "\0" "13" "\0" "14" "\0" "15" "\0" "16" "\0" "17" "\0" "18" "\0" "19" "\0" "1A" "\0" "1B" "\0" "1C" "\0" "1D" "\0" "1E" "\0" "1F" "\0" "20" "\0" "21" "\0" "22" "\0" "23" "\0" "24" "\0" "25" "\0" "26" "\0" "27" "\0" "28" "\0" "29" "\0" "2A" "\0" "2B" "\0" "2C" "\0" "2D" "\0" "2E" "\0" "2F" "\0" "30" "\0" "31" "\0" "32" "\0" "33" "\0" "34" "\0" "35" "\0" "36" "\0" "37" "\0" "38" "\0" "39" "\0" "3A" "\0" "3B" "\0" "3C" "\0" "3D" "\0" "3E" "\0" "3F" "\0" "40" "\0" "41" "\0" "42" "\0" "43" "\0" "44" "\0" "45" "\0" "46" "\0" "47" "\0" "48" "\0" "49" "\0" "4A" "\0" "4B" "\0" "4C" "\0" "4D" "\0" "4E" "\0" "4F" "\0" "50" "\0" "51" "\0" "52" "\0" "53" "\0" "54" "\0" "55" "\0" "56" "\0" "57" "\0" "58" "\0" "59" "\0" "5A" "\0" "5B" "\0" "5C" "\0" "5D" "\0" "5E" "\0" "5F" "\0" "60" "\0" "61" "\0" "62" "\0" "63" "\0" "64" "\0" "65" "\0" "66" "\0" "67" "\0" "68" "\0" "69" "\0" "6A" "\0" "6B" "\0" "6C" "\0" "6D" "\0" "6E" "\0" "6F" "\0" "70" "\0" "71" "\0" "72" "\0" "73" "\0" "74" "\0" "75" "\0" "76" "\0" "77" "\0" "78" "\0" "79" "\0" "7A" "\0" "7B" "\0" "7C" "\0" "7D" "\0" "7E" "\0" "7F" "\0" "80" "\0" "81" "\0" "82" "\0" "83" "\0" "84" "\0" "85" "\0" "86" "\0" "87" "\0" "88" "\0" "89" "\0" "8A" "\0" "8B" "\0" "8C" "\0" "8D" "\0" "8E" "\0" "8F" "\0" "90" "\0" "91" "\0" "92" "\0" "93" "\0" "94" "\0" "95" "\0" "96" "\0" "97" "\0" "98" "\0" "99" "\0" "9A" "\0" "9B" "\0" "9C" "\0" "9D" "\0" "9E" "\0" "9F" "\0" "A0" "\0" "A1" "\0" "A2" "\0" "A3" "\0" "A4" "\0" "A5" "\0" "A6" "\0" "A7" "\0" "A8" "\0" "A9" "\0" "AA" "\0" "AB" "\0" "AC" "\0" "AD" "\0" "AE" "\0" "AF" "\0" "B0" "\0" "B1" "\0" "B2" "\0" "B3" "\0" "B4" "\0" "B5" "\0" "B6" "\0" "B7" "\0" "B8" "\0" "B9" "\0" "BA" "\0" "BB" "\0" "BC" "\0" "BD" "\0" "BE" "\0" "BF" "\0" "C0" "\0" "C1" "\0" "C2" "\0" "C3" "\0" "C4" "\0" "C5" "\0" "C6" "\0" "C7" "\0" "C8" "\0" "C9" "\0" "CA" "\0" "CB" "\0" "CC" "\0" "CD" "\0" "CE" "\0" "CF" "\0" "D0" "\0" "D1" "\0" "D2" "\0" "D3" "\0" "D4" "\0" "D5" "\0" "D6" "\0" "D7" "\0" "D8" "\0" "D9" "\0" "DA" "\0" "DB" "\0" "DC" "\0" "DD" "\0" "DE" "\0" "DF" "\0" "E0" "\0" "E1" "\0" "E2" "\0" "E3" "\0" "E4" "\0" "E5" "\0" "E6" "\0" "E7" "\0" "E8" "\0" "E9" "\0" "EA" "\0" "EB" "\0" "EC" "\0" "ED" "\0" "EE" "\0" "EF" "\0" "F0" "\0" "F1" "\0" "F2" "\0" "F3" "\0" "F4" "\0" "F5" "\0" "F6" "\0" "F7" "\0" "F8" "\0" "F9" "\0" "FA" "\0" "FB" "\0" "FC" "\0" "FD" "\0" "FE" "\0" "FF";
    return &byte_vals_str[byte*3];
}

static size_t hexdump_buffer_to_heap(heap_t *heap, uint8_t *buffer, size_t size){
    const unsigned int space_per_record = sizeof(small_str) * 4;
    size_t ret = 0;
    for (unsigned int i = 0; i < space_per_record && i < size; i++){
        uint8_t byte = 0;
        bpf_probe_read_user(&byte, sizeof(byte), buffer+i);
        ret = read_kernel_str_to_heap(heap, to_hex(byte));
    }
    return ret;
}

static size_t write_named_arg_to_heap(heap_t *heap, small_str name, size_t arg){
    read_kernel_str_to_heap(heap, name);
    heap->taken--;
    read_kernel_str_to_heap(heap, ":");
    if (heap->taken > HEAP_SIZE - sizeof(arg)){
        DEBUG_TRACE("free heap space is less than space_per_record");
        return 0;
    }

    return hexdump_buffer_to_heap(heap, &arg, sizeof(arg));
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
