#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include "trace3.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int ac, char **argv)
{
	struct trace3_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = trace3_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = trace3_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach handler */
	err = trace3_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	read_trace_pipe();

cleanup:
	trace3_bpf__destroy(skel);
	return -err;
}
