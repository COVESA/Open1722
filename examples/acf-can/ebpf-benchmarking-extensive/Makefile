all: build_ebpf build_go

build_ebpf:
	cd eBPF && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

build_go: 
	go generate ./... && mkdir -p bin && go build -o bin/open1722-can-tracing-extensive
	
clean:
	go clean

.PHONY: all build_ebpf build_go clean	