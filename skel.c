#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "skel.skel.h"
#include "skel-def.bpf.h"

#define NAMESPACE(PROJECT, FUNC) PROJECT ## _bpf__ ## FUNC

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

/* It's a global function to make sure compiler doesn't inline it. To be extra
 * sure we also use "asm volatile" and noinline attributes to prevent
 * compiler from local inlining.
 */
__attribute__((noinline)) int uprb(void)
{

  asm volatile ("");
  return 5;
}

static void handle_lost(void *ctx, int cpu, __u64 lost)
{
  fprintf(stdout, "Lost %llu events on CPU #%d!\n", lost, cpu);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
  output_info_t *output_info = data;
  char fmt[] = "%s(%d)->%s:\n";
  fprintf(
      stdout,
      fmt,
      output_info->gen_info.procname,
      output_info->gen_info.pid,
      output_info->gen_info.fname);
}


int main(int argc, char **argv)
{
  struct skel_bpf *skel;
  int err, i;
  LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = NAMESPACE(skel, open_and_load)();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

#define ATTACH_TO(FUNC, IS_RETPROBE, BINARY) \
  { uprobe_opts.func_name = #FUNC; \
    uprobe_opts.retprobe = IS_RETPROBE; \
    skel->links. FUNC = bpf_program__attach_uprobe_opts(skel->progs. FUNC, -1, BINARY, 0, &uprobe_opts); \
    if (!skel->links. FUNC) { err = -errno; fprintf(stderr, "Failed to attach uprobe: %d\n", err); goto cleanup; } }

  for(int i = 1; i < argc; i++){
    ATTACH_TO(uprb, false, argv[i]);
    ATTACH_TO(uprb, true, argv[i]);
  }

  /* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
   * NOTICE: we provide path and symbol info in SEC for BPF programs
   */
  err = NAMESPACE(skel, attach)(skel);
  if (err) {
    fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  struct perf_buffer *pbuf = perf_buffer__new(
      bpf_map__fd(skel->maps.OUTPUT), 128, print_bpf_output, handle_lost, NULL, NULL
  );
  if (!pbuf) {
    err = -errno;
    fprintf(stderr, "Failed to open perf buffer: %d\n", err);
    goto cleanup;
  }

  for (i = 0; i < 100; i++) {
    /* trigger our BPF programs */
    fprintf(stderr, ".");
    uprb();
  }

  while (true) {
    err = perf_buffer__poll(pbuf, 1);
    if (err < 0 && err != -EINTR) {
      fprintf(stderr, "Error while polling perf buffer: %s\n", strerror(err));
      goto cleanup;
    }
    err = 0;
  }

cleanup:
  perf_buffer__free(pbuf);
  NAMESPACE(skel, destroy)(skel);
  return -err;
}
