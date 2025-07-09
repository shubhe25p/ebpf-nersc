#include <linux/bpf.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} race_array SEC(".maps");

static int race_timer_callback(void *race_array, int *race_key, struct bpf_timer *timer)
{
	bpf_timer_start(timer, 1000000, 0);
	return 0;
}

SEC("syscalls")
int race(void *ctx)
{
	struct bpf_timer *timer;
	int err, race_key = 0;
	struct elem init;

	__builtin_memset(&init, 0, sizeof(struct elem));
	bpf_map_update_elem(&race_array, &race_key, &init, BPF_ANY);

	timer = bpf_map_lookup_elem(&race_array, &race_key);
	if (!timer)
		return 1;

	err = bpf_timer_init(timer, &race_array, CLOCK_MONOTONIC);
	if (err && err != -EBUSY)
		return 1;

	bpf_timer_set_callback(timer, race_timer_callback);
	bpf_timer_start(timer, 0, 0);
	bpf_timer_cancel(timer);

	return 0;
}

char _license[] SEC("license") = "GPL";