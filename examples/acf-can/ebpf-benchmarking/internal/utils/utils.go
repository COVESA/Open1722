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
	fmt.Printf("%19s : %-10s %25s\n", "usecs:", "count", "distribution")
	maxCount := sumArray(data)

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
	} {
		count := data[index]
		stars := int(math.Round(float64(count) / float64(maxCount) * float64(maxStars)))
		fmt.Printf("%19s : %-10d |%-50s|\n", range_str, count, strings.Repeat("*", stars))
	}
	fmt.Printf("\n\n\n")

}
