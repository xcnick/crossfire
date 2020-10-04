package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
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

// ParseAddr parses the address in string s
func ParseAddr(s string) (byte, []byte, uint16, error) {
	var atyp byte
	var addr []byte

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return 0, nil, 0, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, net.IPv4len)
			atyp = AtypIP4
			copy(addr[:], ip4)
		} else {
			addr = make([]byte, net.IPv6len)
			atyp = AtypIP6
			copy(addr[:], ip)
		}
	} else {
		if len(host) > 255 {
			return 0, nil, 0, err
		}
		addr = make([]byte, 1+len(host))
		atyp = AtypDomain
		addr[0] = byte(len(host))
		copy(addr[1:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, nil, 0, err
	}

	return atyp, addr, uint16(portnum), err
}
