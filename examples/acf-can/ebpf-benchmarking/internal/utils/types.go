package utils

import "net/netip"

// Config type that needs to be passed to the ebpf program
type Config struct {
	PidSender   uint32
	PidReceiver uint32
	PidCangen   uint32
	SrcIP       [4]byte
	DstIP       [4]byte
	SrcPort     uint32
	DstPort     uint32
	IsKernel    bool
}

type TraceData struct {
	TsEnqueueQdisc    uint64
	TsDequeueQdisc    uint64
	TsNetDevQueue     uint64
	TsNetDevXmitStart uint64
	TsNetDevXmit      uint64
}

type TraceDelays struct {
	QdiscQueuingDelay  uint64
	HardwareQueueDelay uint64
	StackDelay         uint64
}

type Flags struct {
	PidSender   uint
	PidReceiver uint
	PidCangen   uint
	_SrcIP      string
	SrcIP       netip.Addr
	_DstIP      string
	DstIP       netip.Addr
	SrcPort     uint
	DstPort     uint
	IsKernel    bool	//TODO: Add more filters like protocol, check, etc
}
