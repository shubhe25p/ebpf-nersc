from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    char testFileName[16];
    int fdmode;
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t k = {};
    u64 zero = 0, *val;
    bpf_probe_read(&k.testFileName, sizeof(k.testFileName), (void *)PT_REGS_PARM2(ctx));
    k.fdmode = PT_REGS_PARM3(ctx);
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
""")



b.attach_uprobe(name="/usr/lib64/mpi/gcc/openmpi4/lib64/libmpi.so.40", sym="MPI_File_open", fn_name="count")

# header
print("Tracing MPIIO open calls()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# print output
print("%10s %5s %5s %5s %5s" % ("COUNT", "Testfile-name", "fdmode"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\" %12d" % (v.value, k.testFileName.encode('string-escape'), k.fdmode))
