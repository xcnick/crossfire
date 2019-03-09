package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type cipherAeadInfo struct {
	keySize int
	newAead func(key []byte) (cipher.AEAD, error)
}

var cipherAeadMethod = map[string]*cipherAeadInfo{
	"aes-128-gcm":            {16, newAESGCMAead},
	"aes-192-gcm":            {24, newAESGCMAead},
	"aes-256-gcm":            {32, newAESGCMAead},
	"chacha20-ietf-poly1305": {32, newChaCha20Aead},
}

type CipherAead struct {
	enc  cipher.AEAD
	dec  cipher.AEAD
	key  []byte
	salt []byte
	info *cipherAeadInfo
}

func CheckCipherAeadMethod(method string) error {
	if method == "" {
		method = "aes-128-gcm"
	}
	_, ok := cipherAeadMethod[method]
	if !ok {
		return errors.New("unsupported encryption method: " + method)
	}
	return nil
}

func newAESGCMAead(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

func newChaCha20Aead(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, KeySizeError(chacha20poly1305.KeySize)
	}
	return chacha20poly1305.New(key)
}

func NewCipherAead(method, password string) (c *CipherAead, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	mi, ok := cipherAeadMethod[method]
	if !ok {
		return nil, errors.New("unsupported encryption method: " + method)
	}

	key := KDF(password, mi.keySize)
	c = &CipherAead{key: key, info: mi}

	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CipherAead) initEncrypt() (salt []byte, err error) {
	if c.salt == nil {
		salt = make([]byte, c.info.keySize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		c.salt = salt
	} else {
		salt = c.salt
	}

	subkey := make([]byte, c.info.keySize)
	hkdfSHA1(c.key, salt, []byte("ss-subkey"), subkey)
	c.enc, err = c.info.newAead(subkey)
	return
}

func (c *CipherAead) initDecrypt(salt []byte) (err error) {
	subkey := make([]byte, c.info.keySize)
	hkdfSHA1(c.key, salt, []byte("ss-subkey"), subkey)
	c.dec, err = c.info.newAead(subkey)
	return
}

var _zerononce [128]byte // read-only. 128 bytes is more than enough.

func (c *CipherAead) encrypt(dst, src []byte) ([]byte, error) {
	b := c.enc.Seal(dst[c.info.keySize:c.info.keySize], _zerononce[:c.enc.NonceSize()], src, nil)
	return dst[:c.info.keySize+len(b)], nil
}

func (c *CipherAead) decrypt(dst, src []byte) ([]byte, error) {
	b, err := c.dec.Open(dst[:0], _zerononce[:c.dec.NonceSize()], src[c.info.keySize:], nil)
	if err != nil {
		panic(err)
	}
	return b, err
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err) // should never happen
	}
}

func (c *CipherAead) Copy() *CipherAead {
	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}
