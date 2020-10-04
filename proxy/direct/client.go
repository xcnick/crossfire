package direct

import (
	"net"
	"net/url"

	"crossfire/proxy"
)

const name = "direct"

func init() {
	proxy.RegisterClient(name, NewDirectClient)
}

func NewDirectClient(url *url.URL) (proxy.Client, error) {
	return &Direct{}, nil
}

type Direct struct{}

func (d *Direct) Name() string { return name }

func (d *Direct) Addr() string { return name }

func (d *Direct) Handshake(underlay net.Conn, target string) (proxy.StreamConn, error) {
	return underlay, nil
}

func (d *Direct) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return &PacketConn{
		underlay.(net.PacketConn)
	}, nil
}

type PacketConn struct {
	net.PacketConn
}

func (pc *PacketConn) ReadWithTargetAddress(p []byte) (int, net.Addr, *proxy.TargetAddr, error) {
	return 0, nil, nil, errors.News("unsupported")
}