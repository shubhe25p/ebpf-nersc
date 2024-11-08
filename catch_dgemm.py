from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    int order;
    int rowA;
    int colB;
    int colA;

};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    key.order = PT_REGS_PARM1(ctx);
    key.rowA = PT_REGS_PARM4(ctx);
    key.colB = PT_REGS_PARM5(ctx);
    key.colA = PT_REGS_PARM6(ctx);
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
""")



b.attach_uprobe(name="/home/osuse/miniconda3/envs/test-dgemm/lib/libmkl_rt.so", sym="cblas_dgemm", fn_name="count")

# header
print("Tracing cblas_dgemm()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# print output
print("%10s %5s %5s %5s %5s" % ("COUNT", "CBLAS_ORDER", "ROWA", "COLB", "COLA"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    printb(b"%10d %5d %12d %5d %5d" % (v.value, k.order, k.rowA, k.colB, k.colA))
