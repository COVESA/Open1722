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

type EventTrace struct {
	Timestamp uint64
	Pid       uint32
	Uid       uint64
	Function  [32]byte // char[32] -> fixed-size array of 32 bytes
}

type EventTraceRxKernel struct {
	Timestamp uint64
	Dev       [32]byte
}

type EventLog struct {
	Pid                  uint32
	TimestampEnterRead   uint64
	TimestampExitRead    uint64
	TimestampEnterSendto uint64
	TimestampExitSendto  uint64

	TimeReadingCANBus uint64
	TimeWriting       uint64
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
	IsKernel    bool //TODO: Add more filters like protocol, check, etc
}
