package socks5

import (
	"crossfire/common"
	"crossfire/proxy"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const Name = "socks5"

// https://www.ietf.org/rfc/rfc1928.txt

// Version is socks5 version number.
const Version5 = 0x05

// SOCKS auth type
const (
	AuthNone     = 0x00
	AuthPassword = 0x02
)

// SOCKS request commands as defined in RFC 1928 section 4
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

// SOCKS address types as defined in RFC 1928 section 4
const (
	ATypIP4    = 0x1
	ATypDomain = 0x3
	ATypIP6    = 0x4
)

// ParseAddr parse a address string to bytes in socks5 format.
//
//        +------+----------+----------+
//        | ATYP | DST.ADDR | DST.PORT |
//        +------+----------+----------+
//        |  1   | Variable |    2     |
//        +------+----------+----------+
//
func ParseAddr(s string) []byte {
	var addr []byte
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = ATypIP4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = ATypIP6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = ATypDomain
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portnum>>8), byte(portnum)

	return addr
}

// ReadTargetAddr read bytes from conn and create a proxy.TargetAddr
func ReadTargetAddr(r io.Reader) (*proxy.TargetAddr, int, error) {
	reqOneByte := common.GetBuffer(1)
	defer common.PutBuffer(reqOneByte)
	rn := 0

	addr := &proxy.TargetAddr{}
	_, err := io.ReadFull(r, reqOneByte)
	if err != nil {
		return nil, rn, err
	}
	rn += 1

	l := 0
	switch reqOneByte[0] {
	case ATypIP4:
		l = net.IPv4len
		addr.IP = make(net.IP, net.IPv4len)
	case ATypDomain:
		_, err = io.ReadFull(r, reqOneByte)
		if err != nil {
			return nil, rn, err
		}
		rn += 1
		l = int(reqOneByte[0])
	case ATypIP6:
		l = net.IPv6len
		addr.IP = make(net.IP, net.IPv6len)
	default:
		return nil, rn, fmt.Errorf("unknown address type %v", reqOneByte[0])
	}

	reqAddr := common.GetBuffer(l + 2)
	defer common.PutBuffer(reqAddr)
	_, err = io.ReadFull(r, reqAddr)
	if err != nil {
		return nil, rn, err
	}
	rn += l + 2
	if addr.IP != nil {
		copy(addr.IP, reqAddr[:l])
	} else {
		addr.Name = string(reqAddr[:l])
	}
	addr.Port = int(binary.BigEndian.Uint16(reqAddr[l : l+2]))
	return addr, rn, nil
}
