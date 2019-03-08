package shadowsocks

import "testing"

func TestConfigJson(t *testing.T) {
	config, err := ParseConfig("../config.json")
	if err != nil {
		t.Fatal("error parsing config.json:", err)
	}
	if config.Password != "barfoo!" {
		t.Error("wrong password from config")
	}
	if config.Timeout != 600 {
		t.Error("timeout should be 600")
	}
	if config.Method != "aes-128-cfb" {
		t.Error("method should be aes-128-cfb")
	}
}
