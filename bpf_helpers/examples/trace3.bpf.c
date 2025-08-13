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
} hmap SEC(".maps");

static int timer_callback(void* hmap, int* key, struct bpf_timer *timer)
{
        bpf_printk("Callback was invoked do something useful");
	return 0;
}

SEC("cgroup_skb/egress")
int bpf_prog1(void *ctx)
{
	struct bpf_timer *timer;
	int err, key = 0;
	struct elem init;
	struct elem* ele;

	__builtin_memset(&init, 0, sizeof(struct elem));
	bpf_map_update_elem(&hmap, &key, &init, BPF_ANY);

	ele = bpf_map_lookup_elem(&hmap, &key);
	if (!ele)
		return 1;

	timer = &ele->t;
	err = bpf_timer_init(timer, &hmap, CLOCK_MONOTONIC);
	if (err && err != -EBUSY)
		return 1;

	bpf_timer_set_callback(timer, timer_callback);
	bpf_timer_start(timer, 0, 0);
	bpf_timer_cancel(timer); 

	return 0;
}

char _license[] SEC("license") = "GPL";
