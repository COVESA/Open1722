package utils

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

func sumArray(arr []uint64) uint64 {
	var sum uint64 = 0
	for _, value := range arr {
		sum += value
	}
	return sum
}

func PrintHistogram(data []uint64) {
	fmt.Printf("%26s : %-10s %25s\n", "nsecs:", "count", "distribution")
	maxCount := sumArray(data)
	if maxCount == 0 {
		fmt.Printf("No data\n")
		return
	}
	maxStars := 50
	for index, range_str := range []string{
		"0 -> 1",
		"2 -> 3",
		"4 -> 7",
		"8 -> 15",
		"16 -> 31",
		"32 -> 63",
		"64 -> 127",
		"128 -> 255",
		"256 -> 511",
		"512 -> 1023",
		"1024 -> 2047",
		"2048 -> 4095",
		"4096 -> 8191",
		"8192 -> 16383",
		"16384 -> 32767",
		"32768 -> 65535",
		"65536 -> 131071",
		"131072 -> 262143",
		"262144 -> 524287",
		"524288 -> 1048575",
		"1048576 -> 2097151",
		"2097152 -> 4194303",
		"4194304 -> 8388607",
		"8388608 -> 16777215",
		"16777216 -> 33554431",
		"33554432 -> 67108863",
		"67108864 -> 134217727",
		"134217728 -> 268435455",
		"268435456 -> 536870911",
		"536870912 -> 1073741823",
		"1073741824 -> 2147483647",
		"2147483648 -> 4294967295",
		"4294967296 -> 8589934591",
		"8589934592 -> 17179869183",
	} {
		count := data[index]
		stars := int(math.Round(float64(count) / float64(maxCount) * float64(maxStars)))
		fmt.Printf("%26s : %-10d |%-50s|\n", range_str, count, strings.Repeat("*", stars))
	}
	fmt.Printf("\n\n\n")

}

func LogData(logVariable *map[uint32]EventLog, uid uint32, pid uint32, ts uint64, funcName string, dev string) {
	if _, ok := (*logVariable)[uid]; ok {
		//fmt.Println("Uid  found in map")

		if strings.Contains(funcName, "sys_enter_read") || strings.Contains(funcName, "acfcan_tx") {
			eventLog := (*logVariable)[uid]
			eventLog.TimestampEnterRead = ts
			(*logVariable)[uid] = eventLog
		}
		if strings.Contains(funcName, "sys_exit_read") || strings.Contains(funcName, "enter_forward_can_frame") {
			eventLog := (*logVariable)[uid]
			eventLog.TimestampExitRead = ts
			if eventLog.TimestampEnterRead != 0 {
				eventLog.TimeReadingCANBus = ts - eventLog.TimestampEnterRead
			}
			(*logVariable)[uid] = eventLog
		}
		if strings.Contains(funcName, "sys_enter_sendto") || strings.Contains(funcName, "enter_forward_can_frame") {
			eventLog := (*logVariable)[uid]
			eventLog.TimestampEnterSendto = ts
			(*logVariable)[uid] = eventLog
		}
		if strings.Contains(funcName, "sys_exit_sendto") || strings.Contains(funcName, "exit_forward_can_frame") {
			eventLog := (*logVariable)[uid]
			eventLog.TimestampExitSendto = ts
			if eventLog.TimestampEnterSendto != 0 {
				eventLog.TimeWriting = ts - eventLog.TimestampEnterSendto
			}
			(*logVariable)[uid] = eventLog
		}
	} else {
		if strings.Contains(funcName, "sys_enter_read") || strings.Contains(funcName, "acfcan_tx") {
			(*logVariable)[uid] = EventLog{
				Pid:                  pid,
				Dev:                  dev,
				TimestampEnterRead:   ts,
				TimestampExitRead:    0,
				TimestampEnterSendto: 0,
				TimestampExitSendto:  0,
			}
		}
		if strings.Contains(funcName, "sys_exit_read") || strings.Contains(funcName, "enter_forward_can_frame") {
			(*logVariable)[uid] = EventLog{
				Pid:                  pid,
				Dev:                  dev,
				TimestampEnterRead:   0,
				TimestampExitRead:    ts,
				TimestampEnterSendto: 0,
				TimestampExitSendto:  0,
			}
		}
		if strings.Contains(funcName, "sys_enter_sendto") || strings.Contains(funcName, "enter_forward_can_frame") {
			(*logVariable)[uid] = EventLog{
				Pid:                  pid,
				Dev:                  dev,
				TimestampEnterRead:   0,
				TimestampExitRead:    0,
				TimestampEnterSendto: ts,
				TimestampExitSendto:  0,
			}
		}
		if strings.Contains(funcName, "sys_exit_sendto") || strings.Contains(funcName, "exit_forward_can_frame") {
			(*logVariable)[uid] = EventLog{
				Pid:                  pid,
				Dev:                  dev,
				TimestampEnterRead:   0,
				TimestampExitRead:    0,
				TimestampEnterSendto: 0,
				TimestampExitSendto:  ts,
			}
		}
	}
}

func PrintStats(logVariable *map[uint64]EventLog) {
	var readTime []uint64
	var writeTime []uint64
	for _, value := range *logVariable {
		readTime = append(readTime, value.TimeReadingCANBus)
		writeTime = append(writeTime, value.TimeWriting)
	}
	fmt.Println("Read Time", readTime)
	fmt.Println("Write Time", writeTime)
}

func CalculateInterarrivalAndJitter(timestamps []uint64) ([]uint64, float64, error) {
	// Check for minimum required timestamps
	if len(timestamps) < 2 {
		return nil, 0, errors.New("at least two timestamps required")
	}

	// Calculate interarrival times
	interarrivals := make([]uint64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		prev := timestamps[i-1]
		current := timestamps[i]

		if current < prev {
			return nil, 0, errors.New("timestamps must be in non-decreasing order")
		}

		interarrivals[i-1] = current - prev
	}

	// Calculate jitter (average of absolute differences between consecutive interarrivals)
	jitter := 0.0
	if len(interarrivals) >= 2 {
		var sum float64
		for j := 1; j < len(interarrivals); j++ {
			prev := interarrivals[j-1]
			current := interarrivals[j]

			// Calculate absolute difference
			if current > prev {
				sum += float64(current - prev)
			} else {
				sum += float64(prev - current)
			}
		}
		jitter = sum / float64(len(interarrivals)-1)
	}

	return interarrivals, jitter, nil
}
