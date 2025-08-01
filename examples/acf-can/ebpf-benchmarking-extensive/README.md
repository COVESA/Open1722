# Open1722 benchmarking with eBPF

This project demonstrates benchmarking of Open1722 using eBPF and the cilium/ebpf library. Follow the steps below to set up your environment, build the binaries, and run the application.

## 1. Prerequisites

Before you begin, ensure your system meets the following requirements.

### Kernel Requirements

eBPF relies heavily on specific Linux kernel features. The capabilities for kprobes, tracepoints, and uprobes are generally available in modern kernel versions.

- General eBPF Support: Linux kernel 4.4 or newer is required for basic eBPF functionality.
- kprobes: Kernel-level dynamic tracing is available in Linux kernel 4.1 and later. For optimal performance and feature support, a kernel version of 4.14 or newer is recommended.
- tracepoints: Kernel-level static tracing is available in Linux kernel 4.7 and later.
- uprobes: User-space dynamic tracing is available in Linux kernel 4.3 and later.

You'll need a recent version of Go installed on your system. This project is developed and tested with Go 1.18 or newer.

#### Additional Tools

- Make: A build automation tool used to streamline the compilation process.
- Clang/LLVM: Required for compiling the eBPF C code into eBPF bytecode. A version of 9.0 or newer is recommended.
- libbpf-dev: Development headers for the libbpf library.

On a Debian-based system (like Ubuntu), you can install these dependencies with the following command:

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libbpf-dev gcc-multilib g++-multilib
```

## Getting Started

Follow these steps to get your local development environment set up and to build the project binaries.

### Install Go

Download and install Go from the [official website](https://golang.org/dl/):

Set up your Go workspace: Configure your `GOPATH` and `GOBIN` environment variables by adding the following lines to your shell configuration file (e.g., `~/.bashrc` or `~/.zshrc`):

```bash
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:/usr/local/go/bin:$GOBIN
```

After editing the file, reload your shell configuration:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

Verify your installation: Open a new terminal session and run the following command to ensure Go is installed correctly:

```bash
go version
```

## Build the Project

This project uses a Makefile to simplify the build process.

1) You need to make some modifications in the main.go file as per your hardware architecture:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cflags "-I/usr/include/aarch64-linux-gnu -I/usr/include/" CANTrace eBPF/bpf.c
```

When using the go:generate command with bpf2go, the -target flag specifies the architecture for which the eBPF program will be compiled. The supported targets are categorized by their endianness.

#### Possible Targets

The `bpf2go` tool supports the following architectures for the `-target` flag:

**Little-Endian Architectures:**
- `amd64` (x86)
- `arm64`
- `riscv64`
- `loong64`

For these targets, `bpf2go` generates files with the `_bpfel.o` and `_bpfel.go` suffixes, indicating little-endian byte order.

**Big-Endian Architectures:**
- `s390` (and `s390x`)
- `mips`
- `sparc`

For these targets, the generated files will have `_bpfeb.o` and `_bpfeb.go` suffixes, signifying big-endian byte order.

In your specific command, you have correctly used `-target arm64`, which is a valid and supported little-endian architecture.

2) Build the binaries: Run the make command in the root of the eBPF project benchmarking directory (not of Open1722). This will compile the eBPF C code and the Go user-space application.

```bash
make
```

This command will produce the necessary binaries in a designated bin folder.

## Running the Application

Run `open1722-can-tracing-extensive` in `sudo` mode with necessary inputs.

For help, run `sudo open1722-can-tracing-extensive --help`

### Examples

1) Monitoring the userspace talker application, where:
 - The binary is located at `/home/pi/open1722-rs/Open1722-c/examples/build/acf-can/linux/acf-can-talker`
 - PID of the acf-can-talker is 37357

```bash
sudo ./open1722-can-tracing-extensive --pid-talker 37357 --talker-file /home/pi/open1722-rs/Open1722-c/examples/build/acf-can/linux/acf-can-talker
```

2) Monitoring the userspace listener application, where:
 - The binary is located at `/home/pi/open1722-rs/Open1722-c/examples/build/acf-can/linux/acf-can-listener`
 - PID of the acf-can-listener is 37390

```bash
sudo ./open1722-can-tracing-extensive --pid-listener 37390 --listener-file /home/pi/open1722-rs/Open1722-c/examples/build/acf-can/linux/acf-can-listener
```

3) Monitoring the kernel implementation:

```bash
sudo ./open1722-can-tracing-extensive --is-kernel
```
