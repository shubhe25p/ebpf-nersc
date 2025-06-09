#include <bpf/libbpf.h>

void read_trace_pipe(void);
int read_trace_pipe_iter(void (*cb)(const char *str, void *data), void *data, int iter);