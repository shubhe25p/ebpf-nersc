#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace5.skel.h"  // Generated skeleton header
#include "trace_helpers.h"

/* Ring buffer callback function */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
       char *msg = (char *)data;
       printf("Received from ring buffer (%zu bytes): %s\n", data_sz, msg);
       return 0;
}
   
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
   return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
   struct trace5_bpf *skel;
   int err;


   /* Set up libbpf errors and debug info callback */
   libbpf_set_print(libbpf_print_fn);

   /* Open and load BPF application */
   skel = trace5_bpf__open();
   if (!skel) {
       fprintf(stderr, "Failed to open BPF skeleton\n");
       return 1;
   }

   /* Load & verify BPF programs */
   err = trace5_bpf__load(skel);
   if (err) {
       fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
       goto cleanup;
   }

   /* Attach tracepoints */
   err = trace5_bpf__attach(skel);
   if (err) {
       fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
       goto cleanup;
   }

   /* Set up ring buffer polling */
   struct ring_buffer *rb = NULL;
   rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
   if (!rb) {
       fprintf(stderr, "Failed to create ring buffer\n");
       err = -1;
       goto cleanup;
   }
   
   read_trace_pipe();
   /* Poll ring buffer for any submitted data */
   ring_buffer__poll(rb, 100); /* timeout 100ms */


cleanup:
   /* Clean up */
   if (rb)
       ring_buffer__free(rb);
   trace5_bpf__destroy(skel);
   return 0;
}



