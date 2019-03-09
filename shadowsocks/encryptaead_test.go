package shadowsocks

import "testing"

const textAead = "Don't tell me the moon is shining; show me the glint of light on broken glass."

func testCipherAead(t *testing.T, c *CipherAead, msg string) {
	cipherBuf := make([]byte, 64*1024)
	encryBuf, _ := c.encrypt(cipherBuf, []byte(textAead))
	originTxt, _ := c.decrypt(cipherBuf[c.info.keySize:], encryBuf)

	if string(originTxt) != textAead {
		t.Error(msg, " encrypt then decrypt does not get original text")
	}
}

func testBlockCipherAead(t *testing.T, method string) {
	var cipher *CipherAead
	var err error

	cipher, err = NewCipherAead(method, "foobar")
	if err != nil {
		t.Fatal(method, "NewCipher:", err)
	}
	salt, err := cipher.initEncrypt()
	if err != nil {
		t.Error(method, "initEncrypt:", err)
	}
	if err = cipher.initDecrypt(salt); err != nil {
		t.Error(method, "initDecrypt:", err)
	}
	testCipherAead(t, cipher, method)
}

func TestAES128GCM(t *testing.T) {
	testBlockCipherAead(t, "aes-128-gcm")
}

func TestAES192GCM(t *testing.T) {
	testBlockCipherAead(t, "aes-192-gcm")
}

func TestAES256GCM(t *testing.T) {
	testBlockCipherAead(t, "aes-256-gcm")
}

func TestChaCha20Aead(t *testing.T) {
	testBlockCipherAead(t, "chacha20-ietf-poly1305")
}
