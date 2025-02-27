package utils

import (
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
