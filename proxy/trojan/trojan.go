package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	Name = "trojan"
)

var (
	crlf = []byte{'\r', '\n'}
)

// Atyp
const (
	AtypIP4    byte = 1
	AtypDomain byte = 3
	AtypIP6    byte = 4
)

func HexSha224(password string) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write([]byte(password))
	hex.Encode(buf, hash.Sum(nil))
	return buf
}

func SHA224String(password string) string {
	hash := sha256.New224()
	hash.Write([]byte(password))
	val := hash.Sum(nil)
	str := ""
	for _, v := range val {
		str += fmt.Sprintf("%02x", v)
	}
	return str
}
