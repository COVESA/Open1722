package main

import (
	"fmt"
	"log"
	"os"
	"time"

	//"os/exec"
	"os/signal"

	//"strconv"
	//"strings"
	"syscall"

	"github.com/cilium/ebpf"
	link "github.com/cilium/ebpf/link"

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
	// Termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	flags, err := utils.ParseFlags()
	if err != nil {
		fmt.Println("Flag parsing failed: ", err)
	}

	var objs CANTraceObjects
	spec, err := LoadCANTrace()
	if err != nil {
		fmt.Println("Error loading eBPF object: ", err)
	}
	defer objs.Close()

	for name := range spec.Variables {
		fmt.Printf("Available variable: %s\n", name)
	}

	var opts = ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 2,
		},
	}

	/*// Get the variable directly from the map
	configVar, ok := spec.Variables["CONFIG"]
	if !ok {
		panic("CONFIG variable not found in spec")
	}

	// Set the new value
	err = configVar.Set(flags.GetConfig())
	if err != nil {
		panic(err)
	}
	*/
	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG": flags.GetConfig(),
	}); err != nil {
		panic(err)
	}
	err = spec.LoadAndAssign(&objs, &opts)
	if err != nil {
		fmt.Println("Error loading eBPF object: ", err)
	}

	fmt.Println("Loaded eBPF object")

	sysSendtoEnter, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TpEnterSendto, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysSendtoEnter.Close()

	/*sysSendtoExit, err := link.Tracepoint("syscalls", "sys_exit_sendto", objs.TpExitSendto, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysSendtoExit.Close()
	*/
	sysRecvfromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TpEnterRecvfrom, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysRecvfromEnter.Close()

	/*sysRecvfromExit, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TpExitRecvfrom, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysRecvfromExit.Close()
	*/
	fmt.Println("Attached eBPF program to tracepoints")

	var (
		histKey   uint32
		histValue uint64
	)
	hist := objs.Hist
	/*
		histData := map[string]uint64{
			"0 -> 1":            0,
			"2 -> 3":            0,
			"4 -> 7":            0,
			"8 -> 15":           0,
			"16 -> 31":          0,
			"32 -> 63":          0,
			"64 -> 127":         0,
			"128 -> 255":        0,
			"256 -> 511":        0,
			"512 -> 1023":       0,
			"1024 -> 2047":      0,
			"2048 -> 4095":      0,
			"4096 -> 8191":      0,
			"8192 -> 16383":     0,
			"16384 -> 32767":    0,
			"32768 -> 65535":    0,
			"65536 -> 131071":   0,
			"131072 -> 262143":  0,
			"262144 -> 524287":  0,
			"524288 -> 1048575": 0,
		}
	*/
	var histData [21]uint64

	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-sig:
			os.Exit(0)
			fmt.Println("Received termination signal")
			return
		case <-ticker.C:
			iter := hist.Iterate()
			for iter.Next(&histKey, &histValue) {
				histData[histKey] = histValue
			}
			utils.PrintHistogram(histData[:])
		}
	}
}
