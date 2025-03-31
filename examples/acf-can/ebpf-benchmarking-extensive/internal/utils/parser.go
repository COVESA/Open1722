package utils

import "encoding/binary"

func ParseEvents(data []byte) EventTrace {
	var event EventTrace

	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	event.Pid = binary.LittleEndian.Uint32(data[8:12])
	event.Uid = binary.LittleEndian.Uint64(data[12:20])

	copy(event.Function[:], data[20:52])

	return event
}

func ParseEventsRxKernel(data []byte) EventTraceRxKernel {
	var event EventTraceRxKernel

	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	copy(event.Dev[:], data[8:40])

	return event
}
