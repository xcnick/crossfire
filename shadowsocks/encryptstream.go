package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"io"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
)

var errEmptyPassword = errors.New("empty key")

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}

func KDF(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newStream(block, err, key, iv, doe)
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newRC4MD5Stream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)
	return rc4.NewCipher(rc4key)
}

func newChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

func newChaCha20IETFStream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

func newXChaCha20Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	return chacha20.NewCipher(iv, key)
}

type cipherStreamInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var cipherStreamMethod = map[string]*cipherStreamInfo{
	"aes-128-cfb":   {16, aes.BlockSize, newAESCFBStream},
	"aes-192-cfb":   {24, aes.BlockSize, newAESCFBStream},
	"aes-256-cfb":   {32, aes.BlockSize, newAESCFBStream},
	"aes-128-ctr":   {16, aes.BlockSize, newAESCTRStream},
	"aes-192-ctr":   {24, aes.BlockSize, newAESCTRStream},
	"aes-256-ctr":   {32, aes.BlockSize, newAESCTRStream},
	"rc4-md5":       {16, aes.BlockSize, newRC4MD5Stream},
	"chacha20":      {chacha.KeySize, chacha.NonceSize, newChaCha20Stream},
	"chacha20-ietf": {chacha.KeySize, chacha.INonceSize, newChaCha20IETFStream},
	"xchacha20":     {chacha.KeySize, chacha.XNonceSize, newXChaCha20Stream},
}

func CheckCipherStreamMethod(method string) error {
	if method == "" {
		method = "aes-256-cfb"
	}
	_, ok := cipherStreamMethod[method]
	if !ok {
		return errors.New("unsupported encryption method: " + method)
	}
	return nil
}

type CipherStream struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherStreamInfo
	iv   []byte
}

func NewCipherStream(method, password string) (c *CipherStream, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	mi, ok := cipherStreamMethod[method]
	if !ok {
		return nil, errors.New("unsupported encryption method: " + method)
	}

	key := KDF(password, mi.keyLen)
	c = &CipherStream{key: key, info: mi}

	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CipherStream) initEncrypt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		c.iv = iv
	} else {
		iv = c.iv
	}
	c.enc, err = c.info.newStream(c.key, iv, Encrypt)
	return
}

func (c *CipherStream) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

func (c *CipherStream) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *CipherStream) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

func (c *CipherStream) Copy() *CipherStream {
	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}
