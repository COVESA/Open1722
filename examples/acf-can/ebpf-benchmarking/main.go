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

	/*

		sysReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TpEnterRead, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysReadEnter.Close()
	*/
	/*sysSendtoExit, err := link.Tracepoint("syscalls", "sys_exit_sendto", objs.TpExitSendto, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysSendtoExit.Close()
	*/
	/*sysRecvfromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TpEnterRecvfrom, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysRecvfromEnter.Close()*/

	/*sysRecvfromExit, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.TpExitRecvfrom, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to tracepoint: ", err)
	}
	defer sysRecvfromExit.Close()

	fmt.Println("Attached eBPF program to tracepoints")

	kProbeVCanRx, err := link.Kprobe("netif_rx", objs.KprobeNetifRx, nil)
	if err != nil {
		fmt.Println("Error attaching eBPF program to kprobe: ", err)
	}
	defer kProbeVCanRx.Close()
	*/

	if flags.IsKernel {
		fmt.Println("Loaded eBPF objects to trace the kernel version of acf-can")

		kProbeACFCanTx, err := link.Kprobe("acfcan_tx", objs.KprobeAcfcanTx, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kprobe: ", err)
		}
		defer kProbeACFCanTx.Close()

		kProbeFrowardCANFrame, err := link.Kprobe("forward_can_frame", objs.KprobeForwardCanFrame, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kprobe: ", err)
		}
		defer kProbeFrowardCANFrame.Close()

		kProbeIeee1722PacketHanddler, err := link.Kprobe("ieee1722_packet_handdler", objs.KprobeIeee1722PacketHanddler, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kprobe: ", err)
		}
		defer kProbeIeee1722PacketHanddler.Close()
	} else {

		// Tracepoint hook to capture the end of read syscall
		sysReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TpExitRead, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysReadExit.Close()

		// Tracepoint hook to capture the begining of sendto syscall
		sysSendtoEnter, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TpEnterSendto, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysSendtoEnter.Close()

	}
	var (
		histKey   uint32
		histValue uint64
	)
	histSendTo := objs.HistSend
	histRead := objs.HistRead
	histe2e := objs.HistEtoe

	var histDataSento [35]uint64
	var histDataRead [35]uint64
	var histDataE2e [35]uint64

	ticker := time.NewTicker(20 * time.Second)
	for {
		select {
		case <-sig:
			os.Exit(0)
			fmt.Println("Received termination signal")
			return
		case <-ticker.C:
			iter := histSendTo.Iterate()
			for iter.Next(&histKey, &histValue) {
				//fmt.Println("Key: ", histKey, "Value: ", histValue)
				histDataSento[histKey] = histValue
			}
			//fmt.Println("SendTo Histogram")
			//utils.PrintHistogram(histDataSento[:])

			iter = histRead.Iterate()
			for iter.Next(&histKey, &histValue) {
				histDataRead[histKey] = histValue
			}
			fmt.Println("Reading delay (from vcan) histogram")
			utils.PrintHistogram(histDataRead[:])

			iter = histe2e.Iterate()
			for iter.Next(&histKey, &histValue) {
				histDataE2e[histKey] = histValue
			}
			fmt.Println("E2E delay histogram")
			utils.PrintHistogram(histDataE2e[:])
		}
	}
}
