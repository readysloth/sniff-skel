#define XSTR(s) STR(s)
#define STR(s) #s

#define min(x, y) ((x) < (y) ? (x) : (y))
#define DEBUG_TRACE(MSG, ...) \
	bpf_printk("DEBUG_TRACE:%s:%d " MSG, __FILE__, __LINE__, ## __VA_ARGS__)

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE (size_t)2048
#endif

#ifndef SMALL_BUF_SIZE
#define SMALL_BUF_SIZE (size_t)32
#endif

typedef char small_str[SMALL_BUF_SIZE];
typedef char heap_buffer_t[MAX_BUF_SIZE];

typedef struct {
    heap_buffer_t buffer;
    size_t taken;
} heap_t;


#define SMALL_STR_SIZE \
    sizeof(small_str)
#define HEAP_SIZE \
    (sizeof(((heap_t*)NULL)->buffer))
#define FREE_HEAP_SIZE(HEAP_PTR) \
    (HEAP_SIZE - (HEAP_PTR)->taken)
#define FREE_HEAP_PTR(HEAP_PTR) \
    ((HEAP_PTR)->buffer + (HEAP_PTR)->taken)

typedef struct {
    __u64 pid;
    small_str procname;
    small_str fname;
} generic_info_t;

typedef struct {
    generic_info_t gen_info;
    heap_t heap;
} output_info_t;
