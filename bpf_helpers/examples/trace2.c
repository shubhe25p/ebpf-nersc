#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"
#include "trace2.skel.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/* install fake seccomp program to enable seccomp code path inside the kernel,
 * so that our kprobe attached to seccomp_phase1() can be triggered
 */
static void install_accept_all_seccomp(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	if (prctl(PR_SET_SECCOMP, 2, &prog))
		perror("prctl");
}

int main(int ac, char **argv)
{
	FILE *f;
	struct trace2_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = trace2_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = trace2_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = trace2_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	install_accept_all_seccomp();

	f = popen("dd if=/dev/zero of=/dev/null count=5", "r");
	(void) f;

	read_trace_pipe();

cleanup:
	trace2_bpf__destroy(skel);
	return -err;
}
