package trojan

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/url"

	"crossfire/common"
	"crossfire/proxy"
	"crossfire/proxy/socks5"
)

func init() {
	proxy.RegisterClient(Name, NewTrojanClient)
}

func NewTrojanClient(url *url.URL) (proxy.Client, error) {
	addr := url.Host
	user := NewUser(url.User.Username())

	// Create client
	c := &Client{addr: addr, user: user}

	return c, nil
}

// Client is a vmess client
type Client struct {
	addr string
	user *User
}

func (c *Client) Name() string { return Name }

func (c *Client) Addr() string { return c.addr }

func (c *Client) Handshake(underlay net.Conn, target string) (io.ReadWriter, error) {
	conn := &ClientConn{Conn: underlay, target: target, user: c.user}

	// Request
	err := conn.Request()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

type ClientConn struct {
	target string
	user   *User

	net.Conn
	sent uint64
	recv uint64
}

// Request sends request to server.
// https://trojan-gfw.github.io/trojan/protocol
func (c *ClientConn) Request() error {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write([]byte(c.user.Hex))
	buf.Write(crlf)
	buf.WriteByte(socks5.CmdConnect)
	atyp, addr, port, err := ParseAddr(c.target)
	if err != nil {
		return err
	}
	buf.WriteByte(atyp)
	buf.Write(addr)
	err = binary.Write(buf, binary.BigEndian, port) // port
	if err != nil {
		return err
	}
	buf.Write(crlf)
	n, err := c.Conn.Write(buf.Bytes())
	c.sent += uint64(n)

	return err
}

func (c *ClientConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.sent += uint64(n)
	return n, err
}

func (c *ClientConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.recv += uint64(n)
	return n, err
}

func (c *ClientConn) Close() error {
	log.Printf("connection to %v closed, sent: %v, recv: %v", c.target, common.HumanFriendlyTraffic(c.sent), common.HumanFriendlyTraffic(c.recv))
	return c.Conn.Close()
}
