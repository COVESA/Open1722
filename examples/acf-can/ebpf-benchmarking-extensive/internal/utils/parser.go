package utils

import "encoding/binary"

func ParseEvents(data []byte) EventTrace {
	var event EventTrace

	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	event.Pid = binary.LittleEndian.Uint32(data[8:12])
	event.Uid = binary.LittleEndian.Uint32(data[12:16])
	copy(event.Function[:], data[16:48])
	copy(event.Dev[:], data[48:80])
	return event
}

func ParseEventsRxKernel(data []byte) EventTraceRxKernel {
	var event EventTraceRxKernel

	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	copy(event.Dev[:], data[8:40])

	return event
}
