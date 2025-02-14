package main

import (
	"fmt"
	"log"
	//"os"
	//"os/exec"
	//"os/signal"

	//"strconv"
	//"strings"
	//"syscall"

	"github.com/cilium/ebpf"
	//link "github.com/cilium/ebpf/link"
	//"github.com/cilium/ebpf/ringbuf"

	//"open1722-can-tracing/internal/packet"
	//#"open1722-can-tracing/internal/tracertable"
	"open1722-can-tracing/internal/utils"

	//"github.com/spf13/viper"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 CANTrace eBPF/bpf.c
func typeAssertion(b bool) {
	if !b {
		log.Fatalf("Invalid type assertion")
	}
}

func main() {
	flags, err := utils.ParseFlags()
	if err != nil {
		fmt.Println("Flag parsing failed: ", err)
	}

	var opts = ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 2,
		},
	}

	var objs CANTraceObjects
	spec, err := LoadCANTrace()
	if err != nil {
		fmt.Println("Error loading eBPF object: ", err)
	}
	defer objs.Close()

	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG": flags.GetConfig(),
	}); err != nil {
		panic(err)
	}
	err = spec.LoadAndAssign(&objs, &opts)
	if err != nil {
		fmt.Println("Error loading eBPF object: ", err)
	}
}
