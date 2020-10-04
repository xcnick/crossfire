package vless

import (
	"encoding/binary"
	"errors"

	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/url"

	"crossfire/common"
	"crossfire/proxy"
)

func init() {
	proxy.RegisterClient(Name, NewVlessClient)
}

func NewVlessClient(url *url.URL) (proxy.Client, error) {
	addr := url.Host
	uuidStr := url.User.Username()
	uuid, err := StrToUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	query := url.Query()

	encryption := query.Get("encryption")
	if encryption == "" {
		encryption = "none"
	}

	c := &Client{addr: addr}
	user := NewUser(uuid)
	c.users = append(c.users, user)

	//c.opt = OptChunkStream
	//encryption = strings.ToLower(encryption)

	return c, nil
}

// Client is a vmess client
type Client struct {
	addr       string
	users      []*User
	opt        byte
	encryption byte
}

func (c *Client) Name() string { return Name }

func (c *Client) Addr() string { return c.addr }

func (c *Client) Handshake(underlay net.Conn, target string) (io.ReadWriter, error) {
	r := rand.Intn(len(c.users))
	conn := &ClientConn{user: c.users[r], opt: c.opt, encryption: c.encryption}
	conn.Conn = underlay
	var err error
	conn.atyp, conn.addr, conn.port, err = ParseAddr(target)
	if err != nil {
		return nil, err
	}

	// Request
	err = conn.Request()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// ClientConn is a connection to vless server
type ClientConn struct {
	user       *User
	opt        byte
	encryption byte

	atyp byte
	addr []byte
	port uint16

	net.Conn
	dataReader io.Reader
	dataWriter io.Writer
}

// Request sends request to server.
func (c *ClientConn) Request() error {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	// Request
	buf.WriteByte(0)          // Ver
	buf.Write(c.user.UUID[:]) // uuid
	buf.WriteByte(0)          // addon data length

	buf.WriteByte(CmdTCP) // cmd

	// target
	err := binary.Write(buf, binary.BigEndian, c.port) // port
	if err != nil {
		return err
	}

	buf.WriteByte(c.atyp) // atyp
	buf.Write(c.addr)     // addr

	fmt.Println(buf.Bytes())
	_, err = c.Conn.Write(buf.Bytes())

	return err
}

// DecodeRespHeader decodes response header.
func (c *ClientConn) DecodeRespHeader() error {
	b := common.GetBuffer(1)
	defer common.PutBuffer(b)

	_, err := io.ReadFull(c.Conn, b)
	if err != nil {
		return err
	}

	if b[0] != 0 {
		return errors.New("unexpected response version")
	}
	fmt.Println("recv ", b[0])

	_, err = io.ReadFull(c.Conn, b)
	if err != nil {
		return err
	}

	length := int64(b[0])
	fmt.Println("recv length ", length)
	if length != 0 { // addon data length > 0
		io.CopyN(ioutil.Discard, c.Conn, length) // just discard
	}

	return nil
}

func (c *ClientConn) Write(b []byte) (n int, err error) {
	if c.dataWriter != nil {
		return c.dataWriter.Write(b)
	}

	c.dataWriter = c.Conn
	c.dataWriter = ChunkedWriter(c.Conn)

	return c.dataWriter.Write(b)
}

func (c *ClientConn) Read(b []byte) (n int, err error) {
	if c.dataReader != nil {
		return c.dataReader.Read(b)
	}

	err = c.DecodeRespHeader()
	if err != nil {
		return 0, err
	}

	c.dataReader = c.Conn
	c.dataReader = ChunkedReader(c.Conn)

	return c.dataReader.Read(b)
}
