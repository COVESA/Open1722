all: build_ebpf build_go

build_ebpf:
	cd eBPF && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

build_go: 
	go generate ./... && go build

clean:
	go clean

.PHONY: all build_ebpf build_go clean	