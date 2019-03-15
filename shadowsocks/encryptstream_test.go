package shadowsocks

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

const text = "Don't tell me the moon is shining; show me the glint of light on broken glass."

func testCipher(t *testing.T, c *CipherStream, msg string) {
	n := len(text)
	cipherBuf := make([]byte, n)
	originTxt := make([]byte, n)

	c.encrypt(cipherBuf, []byte(text))
	c.decrypt(originTxt, cipherBuf)

	if string(originTxt) != text {
		t.Error(msg, "encrypt then decrypt does not get original text")
	}
}

func TestKDF(t *testing.T) {
	key := KDF("foobar", 32)
	keyTarget := []byte{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c,
		0x66, 0x43, 0x12, 0xc6, 0x3f, 0x56, 0x83, 0x78, 0x52, 0x96, 0x14,
		0xd2, 0x2d, 0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf}
	if !reflect.DeepEqual(key, keyTarget) {
		t.Errorf("key not correct\n\texpect: %v\n\tgot:	%v\n", keyTarget, key)
	}
}

func testBlockCipher(t *testing.T, method string) {
	var cipher *CipherStream
	var err error

	cipher, err = NewCipherStream(method, "foobar")
	if err != nil {
		t.Fatal(method, "NewCipher:", err)
	}
	cipherCopy := cipher.Copy()
	iv, err := cipher.initEncrypt()
	if err != nil {
		t.Error(method, "initEncrypt:", err)
	}
	if err = cipher.initDecrypt(iv); err != nil {
		t.Error(method, "initDecrypt:", err)
	}
	testCipher(t, cipher, method)

	iv, err = cipherCopy.initEncrypt()
	if err != nil {
		t.Error(method, "copy initEncrypt:", err)
	}
	if err = cipherCopy.initDecrypt(iv); err != nil {
		t.Error(method, "copy initDecrypt:", err)
	}
	testCipher(t, cipherCopy, method+" copy")
}

func TestAES128CFB(t *testing.T) {
	testBlockCipher(t, "aes-128-cfb")
}

func TestAES192CFB(t *testing.T) {
	testBlockCipher(t, "aes-192-cfb")
}

func TestAES256CFB(t *testing.T) {
	testBlockCipher(t, "aes-256-cfb")
}

func TestAES128CTR(t *testing.T) {
	testBlockCipher(t, "aes-128-ctr")
}

func TestAES192CTR(t *testing.T) {
	testBlockCipher(t, "aes-192-ctr")
}

func TestAES256CTR(t *testing.T) {
	testBlockCipher(t, "aes-256-ctr")
}

func TestRC4MD5(t *testing.T) {
	testBlockCipher(t, "rc4-md5")
}

func TestChaCha20(t *testing.T) {
	testBlockCipher(t, "chacha20")
}

func TestChaCha20IETF(t *testing.T) {
	testBlockCipher(t, "chacha20-ietf")
}

func TestXChaCha20(t *testing.T) {
	testBlockCipher(t, "xchacha20")
}

var cipherKey = make([]byte, 64)
var cipherIv = make([]byte, 64)

const CIPHER_BENCHMARK_BUFFER_LEN = 4096

func benchmarkCipherInit(b *testing.B, method string) {
	ci := cipherStreamMethod[method]
	key := cipherKey[:ci.keyLen]
	buf := make([]byte, ci.ivLen)
	for i := 0; i < b.N; i++ {
		ci.newStream(key, buf, Encrypt)
	}
}

func BenchmarkAES128CFBInit(b *testing.B) {
	benchmarkCipherInit(b, "aes-128-cfb")
}

func benchmarkCipherEncrypt(b *testing.B, method string) {
	ci := cipherStreamMethod[method]
	key := cipherKey[:ci.keyLen]
	iv := cipherIv[:ci.ivLen]
	enc, err := ci.newStream(key, iv, Encrypt)
	if err != nil {
		b.Error(err)
	}
	src := make([]byte, CIPHER_BENCHMARK_BUFFER_LEN)
	dst := make([]byte, CIPHER_BENCHMARK_BUFFER_LEN)
	io.ReadFull(rand.Reader, src)
	for i := 0; i < b.N; i++ {
		enc.XORKeyStream(dst, src)
	}
}

func BenchmarkAES128CFBEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-128-cfb")
}

func BenchmarkAES256CFBEncrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "aes-256-cfb")
}

func BenchmarkRC4MD5Encrypt(b *testing.B) {
	benchmarkCipherEncrypt(b, "rc4-md5")
}
