clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c biolatency.bpf.c -o biolatency.temp.bpf.o
bpftool gen object biolatency.bpf.o biolatency.temp.bpf.o
bpftool gen skeleton biolatency.bpf.o > biolatency.skel.h
clang -g -Wall -c biolatency.c -o biolatency.o
clang -g -Wall biolatency.o -L/$HOME/libbpf/src -lbpf -lelf -lz -o biolatency

rm biolatency.o biolatency.bpf.o biolatency.temp.bpf.o