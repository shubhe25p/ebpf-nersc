# OS: Linux Kernel 6.4

## Distribution: OpenSUSE Leap 15.6

Reason for OpenSUSE was because of some strange segfaults and binary stripping in Ubuntu Jammy 22.04 both with apt package manager and manual install. (See Issue: https://github.com/bpftrace/bpftrace/issues/954)

## Installing bcc with zypper package manger on OpenSUSE Leap 15.6

The default installation command installs kernel headers at a weird place and not in /lib/modules/$(uname -r), thus bcc might break, a fix would be to manually install kernel headers from this [link](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud-on-AWS-GovCloud-(US)/services/cb-cloud-on-govcloud-sensor-installation-guide/GUID-BDB4D7C7-FAC8-4C52-A9DA-C2C34E456D35.html)

# bpftrace install
```
sudo zypper install bpftrace
```
This installs bpftrace 0.19 with LLVM17

```
sudo bpftrace --info
```
## Useful bpftrace commands

1. Simple bpftrace commands:

```
# This gives the list of bpftrace probes (tracepoints or kprobes or uprobes)
bpftrace -l

# list all the available fields with this tracepoint
bpftrace -vl 'tracepoint:syscalls:sys_enter_read'

# execute a query in one line
bpftrace -e 'BEGIN { printf("Hello world\n"); }'
```

2. A little bit complex bpftrace commands:

```
# list all the process name along with file they read/open with openat syscall
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args.filename);); }'

# syscalls counts with process name as key and count() as built-in function
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# this traces all the read as a histogram as a power of two, with a filter of `dd`
bpftrace -e 'tracepoint:syscalls:sys_exit_read /comm == "dd" / { @bytes = hist(args.ret); }'

```

3. Using kernel dynamic tracing of read and write

```
# use kernel probes to trigger when a vfs read syscall is made, and store it as a linear histogram
# it creates a linear histogram from 0-2000 with 200 as a binsize and the first column represents # the number of bytes read
bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 2000, 200); }'

# total time it takes to read, first probe creates a map with key as thread ID and value as time and second probe creates a another map with key as process name and value as histogram

bpftrace -e 'kprobe:vfs_read {@start[tid] = nsecs; } kretprobe:vfs_read / @start[tid] / { @ns[comm] = hist(nsecs - @start[tid]); delete(@start[tid]); }'

```

4. Other things

```
# get all syscall count with sched with key as probe name and value as number of times its called
bpftrace -e 'tracepoint:sched:sched* {@[probe] = count(); } interval:s:5 {exit(); }'

# profiling cpu kernel stacks at 99Hz and not 100Hz due to some weird reasons
bpftrace -e 'profile:hz:99 { @[kstack]= count(); }'

```

5. Block I/O

```
#during a store to disk, it goes to RAM (block layer) then calls device driver for the storage to do the actual transfer, few tracepoint available:
#tracepoint:block:block_rq_issue -> block io request issued to device driver
#tracepoint:block:block_io_start -> start of a I/O request
#tracepoint:block:block_io_done -> end of an I/O request
#latency = block_io_start - block_io_done ignoring all the intermediate time
#tracepoint:block:block_bio_complete -> a single bio can be broken down into multiple bio or can even be merged, this essentially calculates latency for a single bio

bpftrace -e 'tracepoint:block:block_rq_issue { @=hist(args.bytes ); }'


```

Kernel headers could be replaced by creating a vmlinux.h file, you can create it with this line

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Libbpf code organization:

1. <app>.bpf.c files are the BPF C code that contain the logic which is to be executed in the kernel context;
2. <app>.c is the user-space C code, which loads BPF code and interacts with it throughout the lifetime of the application;
optional 
3. <app>.h is a header file with the common type definitions and is shared by both BPF and user-space code of the applicatio