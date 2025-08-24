/*
 * Copyright (c) 2024, COVESA
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA nor the names of its contributors may be
 *      used to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"encoding/csv"

	"github.com/cilium/ebpf"
	link "github.com/cilium/ebpf/link"

	"github.com/cilium/ebpf/ringbuf"

	"open1722-can-tracing-extensive/internal/utils"

	//hdrhistogram "github.com/HdrHistogram/hdrhistogram-go"
	"github.com/bsipos/thist"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cflags "-I/usr/include/aarch64-linux-gnu -I/usr/include/" CANTrace eBPF/bpf.c

func main() {
	// Termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Get the current working directory to save the histogram images
	baseDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		baseDir = "."
	}

	// Parse command line flags
	flags, err := utils.ParseFlags()
	if err != nil {
		log.Fatalf("Flag parsing failed: %v", err)
	}

	// Load the eBPF object files and assign them to the CANTraceObjects struct
	// This will also rewrite the constants in the eBPF code based on the flags provided	
	var objs CANTraceObjects
	spec, err := LoadCANTrace()
	if err != nil {
		log.Fatalf("Error loading eBPF object: %v", err)
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

	// Load the eBPF objects into the kernel
	err = spec.LoadAndAssign(&objs, &opts)
	if err != nil {
		log.Fatalf("Error loading eBPF object: %v", err)
	}

	fmt.Println("Attached eBPF program to tracepoints")

	// If the flag IsKernel is set, we will attach to kernel probes (kprobes) instead of tracepoints
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

		sysReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TpEnterRead, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysReadEnter.Close()

		sysReadExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TpExitRead, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysReadExit.Close()

		sysSendtoEnter, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TpEnterSendto, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysSendtoEnter.Close()

		sysSendtoExit, err := link.Tracepoint("syscalls", "sys_exit_sendto", objs.TpExitSendto, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysSendtoExit.Close()

		sysRecFromEnter, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.TpEnterRecvfrom, nil)
		if err != nil {
			fmt.Println("Error attaching eBPF program to tracepoint: ", err)
		}
		defer sysRecFromEnter.Close()

		if flags.TalkerFile != "" || flags.ListenerFile != "" {
			if flags.TalkerFile != "" {
				fmt.Println("Loading eBPF objects to trace the user space version of acf-can-talker")

				exTalker, err := link.OpenExecutable(flags.TalkerFile)
				if err != nil {
					fmt.Println("Error opening executable: ", err)
				}
				uprobeCantoAvtp, err := exTalker.Uprobe("can_to_avtp", objs.UprobeCanToAvtp, &link.UprobeOptions{})
				if err != nil {
					fmt.Println("Error attaching eBPF program to UprobeCanToAvtp: ", err)
				}
				defer uprobeCantoAvtp.Close()

				uprobeRetCantoAvtp, err := exTalker.Uretprobe("can_to_avtp", objs.UprobeRetCanToAvtp, &link.UprobeOptions{})
				if err != nil {
					fmt.Println("Error attaching eBPF program to UprobeRetAvtpToCan: ", err)
				}
				defer uprobeRetCantoAvtp.Close()
			}
			if flags.ListenerFile != "" {
				fmt.Println("Loading eBPF objects to trace the user space version of acf-can-listener")

				exListener, err := link.OpenExecutable(flags.ListenerFile)
				if err != nil {
					fmt.Println("Error opening executable: ", err)
				}
				uprobeAvtpToCanListener, err := exListener.Uprobe("avtp_to_can", objs.UprobeAvtpToCan, &link.UprobeOptions{})
				if err != nil {
					fmt.Println("Error attaching eBPF program to UprobeAvtpToCan: ", err)
				}
				defer uprobeAvtpToCanListener.Close()

				uprobeRetAvtpToCanListener, err := exListener.Uretprobe("avtp_to_can", objs.UprobeRetAvtpToCan, &link.UprobeOptions{})
				if err != nil {
					fmt.Println("Error attaching eBPF program to UprobeRetAvtpToCan: ", err)
				}
				defer uprobeRetAvtpToCanListener.Close()
			}
		}
	}
	// Setting up the ring buffer
	rBuf := objs.EventsCanAvtp
	rBufReader, err := ringbuf.NewReader(rBuf)
	if err != nil {
		log.Fatalf("Error creating ring buffer reader: %v", err)
	}
	defer rBufReader.Close()
	cRingBuf := make(chan []byte)

	rBufRx := objs.EventsRecvTs
	rBufReaderRx, err := ringbuf.NewReader(rBufRx)
	if err != nil {
		log.Fatalf("Error creating ring buffer reader: %v", err)
	}
	defer rBufReaderRx.Close()
	cRingBufRx := make(chan []byte)

	var traceDataMapMutex sync.Mutex
	var rxTimestampsKernelMutex sync.Mutex

	traceDataMap := make(map[string]map[uint32]utils.EventLog)
	rxTimestampsKernel := make(map[string][]uint64)

	go func() {
		for {
			select {
			case data := <-cRingBuf:
				parsedEvent := utils.ParseEvents(data)
				functionStr := string(parsedEvent.Function[:])
				functionStr = strings.TrimRight(functionStr, "\x00")

				devStr := string(parsedEvent.Dev[:])
				devStr = strings.TrimRight(devStr, "\x00")

				traceDataMapMutex.Lock()
				if traceDataMap[devStr] == nil {
					traceDataMap[devStr] = make(map[uint32]utils.EventLog)
				}
				if value, ok := traceDataMap[devStr]; ok {
					utils.LogData(&value, parsedEvent.Uid, parsedEvent.Pid, parsedEvent.Timestamp, functionStr, devStr)
					traceDataMap[devStr] = value
				} else {
					tempMap := make(map[uint32]utils.EventLog)
					utils.LogData(&tempMap, parsedEvent.Uid, parsedEvent.Pid, parsedEvent.Timestamp, functionStr, devStr)
					traceDataMap[devStr] = tempMap
				}
				traceDataMapMutex.Unlock()
			case data := <-cRingBufRx:
				rxData := utils.ParseEventsRxKernel(data).Dev
				dev := string(rxData[:])
				dev = strings.TrimRight(dev, "\x00")

				rxTimestampsKernelMutex.Lock() 
				rxTimestampsKernel[dev] = append(rxTimestampsKernel[dev], uint64(utils.ParseEventsRxKernel(data).Timestamp))
				rxTimestampsKernelMutex.Unlock()
			}
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-sig:
			counter := 0

			now := time.Now()
			fileNameEventsCanAvtp := fmt.Sprintf("EventsCanAvtp_%s.csv", now.Format("20060102_150405"))
			fileNameEventsRecvTs := fmt.Sprintf("EventsRecvTs_%s.csv", now.Format("20060102_150405"))

			fileEventsCanAvtp, err := os.Create(fileNameEventsCanAvtp)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			// Explicitly close fileEventsCanAvtp before exiting
			defer func() {
				if err := fileEventsCanAvtp.Close(); err != nil {
					fmt.Println("Error closing fileEventsCanAvtp:", err)
				}
			}()

			fileEventsRecvTs, err := os.Create(fileNameEventsRecvTs)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			// Explicitly close fileEventsRecvTs before exiting
			defer func() {
				if err := fileEventsRecvTs.Close(); err != nil {
					fmt.Println("Error closing fileEventsRecvTs:", err)
				}
			}()

			writerfileEventsCanAvtp := csv.NewWriter(fileEventsCanAvtp)
			defer writerfileEventsCanAvtp.Flush()
			writerfileEventsCanAvtp.Write([]string{"PID", "Dev", "TimestampEnterRead", "TimestampExitRead", "TimeReadingCANBus", "TimestampEnterSendto", "TimestampExitSendto", "TimeWriting", "TimestampEnterCanToAvtp", "TimestampExitCanToAvtp", "TimeCanToAvtp", "TimestampEnterAvtpToCan", "TimestampExitAvtpToCan", "TimeAvtpToCan"})
			
			traceDataMapMutex.Lock()
			for _, tData := range traceDataMap {
				fmt.Println("Results")
				histReadingTime := thist.NewHist(nil, "CAN bus reading time histogram (in nanoseconds)", "fixed", 20, true)
				histSendingTime := thist.NewHist(nil, "Sending time (in nanoseconds)", "fixed", 20, true)
				histCanToAvtp := thist.NewHist(nil, "CAN to AVTP time histogram (in nanoseconds)", "fixed", 20, true)
				histAvtpToCan := thist.NewHist(nil, "AVTP to CAN time histogram (in nanoseconds)", "fixed", 20, true)

				for _, value := range tData {
					//fmt.Println("Value: ", value)
					histReadingTime.Title = "CAN bus reading time histogram (in nanoseconds) for " + string(value.Dev[:])
					histSendingTime.Title = "Sending time (in nanoseconds) for " + string(value.Dev[:])
					histCanToAvtp.Title = "CAN to AVTP time histogram (in nanoseconds) for " + string(value.Dev[:])
					histAvtpToCan.Title = "AVTP to CAN time histogram (in nanoseconds) for " + string(value.Dev[:])
					if value.TimestampEnterRead != 0 && value.TimestampExitRead != 0 {
						histReadingTime.Update(float64(value.TimeReadingCANBus))
					}
					if value.TimestampEnterSendto != 0 && value.TimestampExitSendto != 0 {
						histSendingTime.Update(float64(value.TimeWriting))
					}
					if value.TimestampEnterCanToAvtp != 0 && value.TimestampExitCanToAvtp != 0 {
						histCanToAvtp.Update(float64(value.TimeCanToAvtp))
					}
					if value.TimestampEnterAvtpToCan != 0 && value.TimestampExitAvtpToCan != 0 {
						histAvtpToCan.Update(float64(value.TimeAvtpToCan))
					}
					writerfileEventsCanAvtp.Write([]string{fmt.Sprintf("%d", value.Pid),
						value.Dev,
						fmt.Sprintf("%d", value.TimestampEnterRead),
						fmt.Sprintf("%d", value.TimestampExitRead),
						fmt.Sprintf("%d", value.TimeReadingCANBus),
						fmt.Sprintf("%d", value.TimestampEnterSendto),
						fmt.Sprintf("%d", value.TimestampExitSendto),
						fmt.Sprintf("%d", value.TimeWriting),
						fmt.Sprintf("%d", value.TimestampEnterCanToAvtp),
						fmt.Sprintf("%d", value.TimestampExitCanToAvtp),
						fmt.Sprintf("%d", value.TimeCanToAvtp),
						fmt.Sprintf("%d", value.TimestampEnterAvtpToCan),
						fmt.Sprintf("%d", value.TimestampExitAvtpToCan),
						fmt.Sprintf("%d", value.TimeAvtpToCan)})
				}

				fmt.Println(histReadingTime.Draw())
				fmt.Println(histSendingTime.Draw())
				fmt.Println(histCanToAvtp.Draw())
				fmt.Println(histAvtpToCan.Draw())

				counter++
				filename := fmt.Sprintf("%s/histogram_%d.png", baseDir, counter)
				histReadingTime.SaveImage(filename)

				counter++
				filename = fmt.Sprintf("%s/histogram_%d.png", baseDir, counter)
				histSendingTime.SaveImage(filename)

				counter++
				filename = fmt.Sprintf("%s/histogram_%d.png", baseDir, counter)
				histCanToAvtp.SaveImage(filename)

				counter++
				filename = fmt.Sprintf("%s/histogram_%d.png", baseDir, counter)
				histAvtpToCan.SaveImage(filename)
			}
			traceDataMapMutex.Unlock()

			// Write the received timestamps to a CSV file
			rxTimestampsKernelMutex.Lock()
			writerfileEventsRecvTs := csv.NewWriter(fileEventsRecvTs)
			defer writerfileEventsRecvTs.Flush()
			writerfileEventsRecvTs.Write([]string{"Key", "InterarrivalTime (in nanoseconds)", "Jitter"})

			var jitter float64
			var interarrivalTime []uint64
			for key, value := range rxTimestampsKernel {
				histInterarrivalTime := thist.NewHist(nil, "Interarrival time (in nanoseconds)", "fixed", 20, true)
				interarrivalTime, jitter, err = utils.CalculateInterarrivalAndJitter(value)
				if err != nil {
					fmt.Println("Error calculating interarrival time and jitter: ", err)
				}
				for _, value := range interarrivalTime {
					histInterarrivalTime.Update(float64(value))
					writerfileEventsRecvTs.Write([]string{key, fmt.Sprintf("%d", value), fmt.Sprintf("%f", jitter)})
				}
				histInterarrivalTime.Title = "Interarrival time (in nanoseconds) for " + key
				fmt.Println(histInterarrivalTime.Draw())
				fmt.Println("Jitter at ", key, " : ", jitter)

				counter++
				filename := fmt.Sprintf("%s/histogram_%d.png", baseDir, counter)
				histInterarrivalTime.SaveImage(filename)
			}
			rxTimestampsKernelMutex.Unlock()
			
			fmt.Println("Received termination signal")
			os.Exit(0)
			return
		case <-ticker.C:
			fmt.Println("Ticker triggered...")
			for rBufReader.AvailableBytes() > 0 {
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
