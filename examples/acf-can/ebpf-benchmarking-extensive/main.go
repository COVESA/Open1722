package main

import (
	"encoding/binary"
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
		fmt.Println("Loaded eBPF objects to trace the kernel version of acf-can")

		kProbeACFCanTx, err := link.Kprobe("acfcan_tx", objs.KprobeAcfcanTx, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kprobe: ", err)
		}
		defer kProbeACFCanTx.Close()

		kProbeExitACFCanTx, err := link.Kretprobe("acfcan_tx", objs.KretprobeAcfcanTx, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kretprobe: ", err)
		}
		defer kProbeExitACFCanTx.Close()

		kProbeEntryFrowardCANFrame, err := link.Kprobe("forward_can_frame", objs.KprobeEntryForwardCanFrame, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kprobe: ", err)
		}
		defer kProbeEntryFrowardCANFrame.Close()

		kProbeExitFrowardCANFrame, err := link.Kretprobe("forward_can_frame", objs.KretprobeExitForwardCanFrame, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kretprobe: ", err)
		}
		defer kProbeExitFrowardCANFrame.Close()

		kProbeIeee1722PacketHanddler, err := link.Kprobe("ieee1722_packet_handdler", objs.KprobeIeee1722PacketHanddler, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to kprobe: ", err)
		}
		defer kProbeIeee1722PacketHanddler.Close()
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
		sysRecFromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TpEnterRecvfrom, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysRecFromEnter.Close()
	}

	// Setting up the ring buffer
	rBuf := objs.EventsCanAvtp
	rBufReader, err := ringbuf.NewReader(rBuf)
	if err != nil {
		fmt.Println("Error creating ring buffer reader: ", err)
	}
	defer rBufReader.Close()
	cRingBuf := make(chan []byte)

	rBufRx := objs.EventsRecvTs
	rBufReaderRx, err := ringbuf.NewReader(rBufRx)
	if err != nil {
		fmt.Println("Error creating ring buffer reader: ", err)
	}
	defer rBufReaderRx.Close()
	cRingBufRx := make(chan []byte)

	//traceData := make(map[uint64]utils.EventLog)
	traceDataMap := make(map[string]map[uint32]utils.EventLog)
	//histReadingTime := thist.NewHist(nil, "CAN bus reading time histogram (in nanoseconds)", "fixed", 12, true)
	//histSendingTime := thist.NewHist(nil, "Sending time (in nanoseconds)", "fixed", 12, true)

	var rxTimestamps []uint64
	rxTimestampsKernel := make(map[string][]uint64)

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
				dev := utils.ParseEvents(data).Dev
				devStr := string(dev[:])
				devStr = strings.TrimRight(devStr, "\x00")
				if traceDataMap[devStr] == nil {
					traceDataMap[devStr] = make(map[uint32]utils.EventLog)
				}
				if value, ok := traceDataMap[devStr]; ok {
					utils.LogData(&value, utils.ParseEvents(data).Uid, utils.ParseEvents(data).Pid, utils.ParseEvents(data).Timestamp, functionStr, devStr)
					traceDataMap[devStr] = value
				} else {
					tempMap := make(map[uint32]utils.EventLog)
					utils.LogData(&tempMap, utils.ParseEvents(data).Uid, utils.ParseEvents(data).Pid, utils.ParseEvents(data).Timestamp, functionStr, devStr)
					traceDataMap[devStr] = tempMap
				}
				// 	tempMap := traceDataMap[devStr]
				// 	utils.LogData(&tempMap, utils.ParseEvents(data).Uid, utils.ParseEvents(data).Pid, utils.ParseEvents(data).Timestamp, functionStr)
				// 	traceDataMap[devStr] = tempMap
				//	utils.PrintStats(&traceData)

			case data := <-cRingBufRx:
				//fmt.Println("Received event from ring buffer")
				if flags.IsKernel {
					rxData := utils.ParseEventsRxKernel(data).Dev
					dev := string(rxData[:])
					dev = strings.TrimRight(dev, "\x00")
					//fmt.Println("Dev: ", dev, " Timestamp: ", utils.ParseEventsRxKernel(data).Timestamp)
					rxTimestampsKernel[dev] = append(rxTimestampsKernel[dev], uint64(utils.ParseEventsRxKernel(data).Timestamp))
				}
				if flags.PidTalker != 0 {
					rxTimestamps = append(rxTimestamps, uint64(binary.LittleEndian.Uint64(data)))
				}
			}

		}

	}()

	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-sig:
			/*
				for _, value := range traceData {
					histReadingTime.Update(float64(value.TimeReadingCANBus))
					histSendingTime.Update(float64(value.TimeWriting))
					histToExportReadingTime.RecordValue(int64(value.TimeReadingCANBus))
					histToExporSendingTime.RecordValue(int64(value.TimeWriting))
				}
				fmt.Println(histReadingTime.Draw())
				fmt.Println(histSendingTime.Draw())*/
			counter := 0
			for _, tData := range traceDataMap {
				histReadingTime := thist.NewHist(nil, "CAN bus reading time histogram (in nanoseconds)", "auto", 12, true)
				histSendingTime := thist.NewHist(nil, "Sending time (in nanoseconds)", "auto", 12, true)
				histToExportReadingTime := hdrhistogram.New(1, 1000000, 3)
				histToExporSendingTime := hdrhistogram.New(1, 1000000, 3)
				for _, value := range tData {
					//fmt.Println("key:",key, "- Device: ", value)
					histReadingTime.Title = "CAN bus reading time histogram (in nanoseconds) for" + string(value.Dev[:])
					histSendingTime.Title = "Sending time (in nanoseconds) for" + string(value.Dev[:])
					if value.TimestampExitRead != 0 {
						histReadingTime.Update(float64(value.TimeReadingCANBus))
						histToExportReadingTime.RecordValue(int64(value.TimeReadingCANBus))
					}
					if value.TimestampEnterSendto != 0 && value.TimestampExitSendto != 0 {
						histSendingTime.Update(float64(value.TimeWriting))
						histToExporSendingTime.RecordValue(int64(value.TimeWriting))
					}
				}
				fmt.Println(histReadingTime.Draw())
				fmt.Println(histSendingTime.Draw())

				counter++
				filename := fmt.Sprintf("/home/rng-c-002/ieee1722_open_avtp/Open1722/examples/acf-can/ebpf-benchmarking-extensive/histograms/histogram_%d.png", counter)
				histReadingTime.SaveImage(filename)

				counter++
				filename = fmt.Sprintf("/home/rng-c-002/ieee1722_open_avtp/Open1722/examples/acf-can/ebpf-benchmarking-extensive/histograms/histogram_%d.png", counter)
				histSendingTime.SaveImage(filename)
			}

			var jitter float64
			var interarrivalTime []uint64
			if flags.IsKernel {
				for key, value := range rxTimestampsKernel {
					histInterarrivalTime := thist.NewHist(nil, "Interarrival time (in nanoseconds)", "auto", 10, true)
					interarrivalTime, jitter, err = utils.CalculateInterarrivalAndJitter(value)
					if err != nil {
						fmt.Println("Error calculating interarrival time and jitter: ", err)
					}
					//fmt.Println("Interarrival time: ", interarrivalTime)
					for _, value := range interarrivalTime {
						histInterarrivalTime.Update(float64(value))
					}
					histInterarrivalTime.Title = "Interarrival time (in nanoseconds) for " + key
					fmt.Println(histInterarrivalTime.Draw())
					fmt.Println("Jitter at ", key, " : ", jitter)

					counter++
					filename := fmt.Sprintf("/home/rng-c-002/ieee1722_open_avtp/Open1722/examples/acf-can/ebpf-benchmarking-extensive/histograms/histogram_%d.png", counter)
					histInterarrivalTime.SaveImage(filename)
				}
			}
			if flags.PidTalker != 0 && !flags.IsKernel {
				histInterarrivalTime := thist.NewHist(nil, "Interarrival time (in nanoseconds)", "fixed", 10, true)
				interarrivalTime, jitter, err = utils.CalculateInterarrivalAndJitter(rxTimestamps)
				if err != nil {
					fmt.Println("Error calculating interarrival time and jitter: ", err)
				}
				//fmt.Println("Interarrival time: ", interarrivalTime)
				for _, value := range interarrivalTime {
					histInterarrivalTime.Update(float64(value))
				}
				fmt.Println(histInterarrivalTime.Draw())
				fmt.Println("Jitter: ", jitter)
			}
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

			for rBufReaderRx.AvailableBytes() > 0 {
				event, err := rBufReaderRx.Read()
				if err != nil {
					log.Fatalf("Error reading ringbuf: %v", err)
				}
				cRingBufRx <- event.RawSample
			}
		}
	}
}
