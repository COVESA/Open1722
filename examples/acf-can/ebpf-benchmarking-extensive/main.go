package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	link "github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/ringbuf"

	"open1722-can-tracing-extensive/internal/utils"
	//"github.com/spf13/viper"
	hdrhistogram "github.com/HdrHistogram/hdrhistogram-go"
	"github.com/bsipos/thist"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 CANTrace eBPF/bpf.c

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

	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG": flags.GetConfig(),
	}); err != nil {
		panic(err)
	}
	err = spec.LoadAndAssign(&objs, &opts)
	if err != nil {
		fmt.Println("Error loading eBPF object: ", err)
	}

	fmt.Println("Attached eBPF program to tracepoints")

	if flags.IsKernel {
		/*fmt.Println("Loaded eBPF objects to trace the kernel version of acf-can")

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
		defer kProbeIeee1722PacketHanddler.Close()*/
	} else {

		// Tracepoint hook to capture the start of read syscall
		sysReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TpEnterRead, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysReadEnter.Close()

		// Tracepoint hook to capture the end of read syscall
		sysReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TpExitRead, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysReadExit.Close()

		// Tracepoint hook to capture the start of sendto syscall
		sysSendtoEnter, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TpEnterSendto, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysSendtoEnter.Close()

		// Tracepoint hook to capture the end of sendto syscall
		sysSendtoExit, err := link.Tracepoint("syscalls", "sys_exit_sendto", objs.TpExitSendto, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysSendtoExit.Close()

		// Tracepoint hook to capture the begining of recvmsg syscall
		/*sysSendEnter, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.TpEnterSendto, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysSendEnter.Close()*/
	}

	// Setting up the ring buffer
	rBuf := objs.EventsCanAvtp
	rBufReader, err := ringbuf.NewReader(rBuf)
	if err != nil {
		fmt.Println("Error creating ring buffer reader: ", err)
	}
	defer rBufReader.Close()
	cRingBuf := make(chan []byte)

	traceData := make(map[uint64]utils.EventLog)
	histReadingTime := thist.NewHist(nil, "CAN bus reading time histogram (in nanoseconds)", "fixed", 12, true)
	histSendingTime := thist.NewHist(nil, "Sending time (in nanoseconds)", "fixed", 12, true)
	histToExportReadingTime := hdrhistogram.New(1, 1000000, 3)
	histToExporSendingTime := hdrhistogram.New(1, 1000000, 3)

	/*go func() {
		for {
			event, err := rBufReader.Read()
			if err != nil {
				log.Fatalf("Error reading ringbuf: %v", err)
			}
			cRingBuf <- event.RawSample
		}
	}()*/

	go func() {
		for {
			select {
			case data := <-cRingBuf:
				//fmt.Println("Received event from ring buffer")
				function := utils.ParseEvents(data).Function
				functionStr := string(function[:])
				functionStr = strings.TrimRight(functionStr, "\x00")
				//fmt.Println("Uid: ", utils.ParseEvents(data).Uid, " Pid: ", utils.ParseEvents(data).Pid, " Timestamp: ", utils.ParseEvents(data).Timestamp, " Function: ", functionStr)
				utils.LogData(&traceData, utils.ParseEvents(data).Uid, utils.ParseEvents(data).Pid, utils.ParseEvents(data).Timestamp, functionStr)
				//utils.PrintStats(&traceData)

			}
		}

	}()

	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-sig:
			for _, value := range traceData {
				histReadingTime.Update(float64(value.TimeReadingCANBus))
				histSendingTime.Update(float64(value.TimeWriting))
				histToExportReadingTime.RecordValue(int64(value.TimeReadingCANBus))
				histToExporSendingTime.RecordValue(int64(value.TimeWriting))
			}
			fmt.Println(histReadingTime.Draw())
			fmt.Println(histSendingTime.Draw())
			os.Exit(0)
			fmt.Println("Received termination signal")
			return
		case <-ticker.C:
			fmt.Println("Ticker triggered")
			for rBufReader.AvailableBytes() > 0 {
				//fmt.Println("Available bytes in ring buffer: ", rBufReader.AvailableBytes())
				event, err := rBufReader.Read()
				if err != nil {
					log.Fatalf("Error reading ringbuf: %v", err)
				}
				cRingBuf <- event.RawSample
			}
		}
	}

}
