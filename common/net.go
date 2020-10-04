package common

import (
	"fmt"
)

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024

	// TCPBufSize is the size of tcp buffer
	TCPBufSize = 16 << 10

	// UDPBufSize is the size of udp buffer, 2^16 = 65536
	UDPBufSize = 64 << 10
)

func HumanFriendlyTraffic(bytes uint64) string {
	if bytes <= KiB {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes <= MiB {
		return fmt.Sprintf("%.2f KiB", float32(bytes)/KiB)
	}
	if bytes <= GiB {
		return fmt.Sprintf("%.2f MiB", float32(bytes)/MiB)
	}
	return fmt.Sprintf("%.2f GiB", float32(bytes)/GiB)
}
