package shadowsocks

import "fmt"

// PrintVersion 打印版本
func PrintVersion() {
	const version = "0.0.1"
	fmt.Println("shadowsocks-lite version ", version)
}
