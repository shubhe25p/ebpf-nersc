#include <vmlinux.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>

 SEC("kprobe/__arm64_sys_write")
 void bpf_func___arm64_sys_write(struct pt_regs *ctx)
 {
     char fmt[] = "write() called \n";
     bpf_trace_printk(fmt, sizeof(fmt));
 }

 struct {
     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
     __uint(key_size, sizeof(u32));
     __uint(max_entries, 1);
     __array(values, u32 (void *));
 } progs SEC(".maps") = {
     .values = {
         [0] = (void *)&bpf_func___arm64_sys_write
     },
 };

 SEC("kprobe/__seccomp_filter")
 int bpf_prog1(struct pt_regs *ctx)
 {
     int sc_nr = (int)PT_REGS_PARM1(ctx);

     /* dispatch into next BPF program depending on syscall number */
     if (sc_nr == 1)
         bpf_tail_call(ctx, &progs, 0);
     return 0;
 }
 char _license[] SEC("license") = "GPL";
