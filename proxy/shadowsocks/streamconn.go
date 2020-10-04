package shadowsocks

import (
	"bytes"
	"io"
	"net"
	"sync"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1
const bufSize = 17 * 1024

var bufPool = sync.Pool{New: func() interface{} { return make([]byte, bufSize) }}

type StreamConn struct {
	net.Conn
	*CipherAead
	rnonce   []byte
	wnonce   []byte
	leftover []byte
}

// NewStreamConn wraps a stream-oriented net.Conn with cipher.
func NewStreamConn(c net.Conn, ciph *CipherAead) *StreamConn {
	return &StreamConn{
		Conn:       c,
		CipherAead: ciph,
	}
}

func (c *StreamConn) Close() error {
	return c.Conn.Close()
}

func DialWithRawAddr(rawaddr []byte, server string, cipher *CipherAead) (c *StreamConn, err error) {
	// 连接服务器，即ss-server
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}

	// 将ss-server连接与加密方式一起封装
	c = NewStreamConn(conn, cipher)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

/*
   Handles basic aead process of shadowsocks protocol

   TCP Chunk (after encryption, *ciphertext*)
   +--------------+---------------+--------------+------------+
   |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
   +--------------+---------------+--------------+------------+
   |      2       |     Fixed     |   Variable   |   Fixed    |
   +--------------+---------------+--------------+------------+

   UDP (after encryption, *ciphertext*)
   +--------+-----------+-----------+
   | NONCE  |  *Data*   |  Data_TAG |
   +-------+-----------+-----------+
   | Fixed  | Variable  |   Fixed   |
   +--------+-----------+-----------+
*/
func (c *StreamConn) Write(b []byte) (n int, err error) {
	if c.enc == nil {
		_, err = c.initEncrypt()
		if err != nil {
			return
		}
		_, err = c.Conn.Write(c.salt)
		if err != nil {
			return 0, err
		}
		c.wnonce = make([]byte, c.enc.NonceSize())
	}

	writeBuf := bufPool.Get().([]byte)
	defer bufPool.Put(writeBuf)
	r := io.Reader(bytes.NewBuffer(b))
	for {
		payloadBuf := writeBuf[2+c.enc.Overhead() : 2+c.enc.Overhead()+payloadSizeMask]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += nr
			writeBuf = writeBuf[:2+c.enc.Overhead()+nr+c.enc.Overhead()]
			payloadBuf = payloadBuf[:nr]
			writeBuf[0], writeBuf[1] = byte(nr>>8), byte(nr) // big-endian payload size
			c.enc.Seal(writeBuf[:0], c.wnonce, writeBuf[:2], nil)
			increment(c.wnonce)

			c.enc.Seal(payloadBuf[:0], c.wnonce, payloadBuf, nil)
			increment(c.wnonce)

			_, ew := c.Conn.Write(writeBuf)
			if ew != nil {
				err = ew
				return
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF
				err = er
			}
			break
		}
	}
	return
}

func (c *StreamConn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		salt := make([]byte, c.info.keySize)
		if _, err = io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}
		if err = c.initDecrypt(salt); err != nil {
			return 0, err
		}
		c.rnonce = make([]byte, c.dec.NonceSize())
	}
	readBuf := bufPool.Get().([]byte)
	defer bufPool.Put(readBuf)
	if len(c.leftover) > 0 {
		n = copy(b, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}

	cipherData := readBuf[:2+c.dec.Overhead()]
	_, err = io.ReadFull(c.Conn, cipherData)
	if err != nil {
		return 0, err
	}
	_, err = c.dec.Open(cipherData[:0], c.rnonce, cipherData, nil)
	increment(c.rnonce)
	if err != nil {
		return 0, err
	}

	size := (int(cipherData[0])<<8 + int(cipherData[1])) & payloadSizeMask
	// decrypt payload
	cipherData = readBuf[:size+c.dec.Overhead()]
	_, err = io.ReadFull(c.Conn, cipherData)
	if err != nil {
		return 0, err
	}

	_, err = c.dec.Open(cipherData[:0], c.rnonce, cipherData, nil)
	increment(c.rnonce)
	if err != nil {
		return 0, err
	}

	n = copy(b, readBuf[:size])
	if n < size {
		c.leftover = readBuf[n:size]
	}

	return n, err
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
