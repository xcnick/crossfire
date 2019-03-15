package shadowsocks

import (
	"io"
	"net"
)

type PackConn struct {
	net.Conn
	*CipherAead
	readBuf  []byte
	writeBuf []byte
}

func NewPackConn(c net.Conn, cipher *CipherAead) *PackConn {
	return &PackConn{
		Conn:       c,
		CipherAead: cipher,
		readBuf:    leakyBuf.Get(),
		writeBuf:   leakyBuf.Get()}
}

func (c *PackConn) Close() error {
	leakyBuf.Put(c.readBuf)
	leakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

func (c *PackConn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		salt := make([]byte, c.info.keySize)
		if _, err = io.ReadFull(c.Conn, salt); err != nil {
			return
		}
		if err = c.initDecrypt(salt); err != nil {
			return
		}
		if len(c.salt) == 0 {
			c.salt = salt
		}
	}

	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *PackConn) Write(b []byte) (n int, err error) {
	var salt []byte
	if c.enc == nil {
		salt, err = c.initEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := c.writeBuf
	dataSize := len(b) + len(salt)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if salt != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, salt)
	}

	c.encrypt(cipherData[len(salt):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
