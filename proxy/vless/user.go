package vless

import (
	"encoding/hex"
	"errors"
	"strings"
)

// Vmess user
type User struct {
	UUID [16]byte
}

func NewUser(uuid [16]byte) *User {
	u := &User{UUID: uuid}
	return u
}

// StrToUUID converts string to uuid
func StrToUUID(s string) (uuid [16]byte, err error) {
	b := []byte(strings.Replace(s, "-", "", -1))
	if len(b) != 32 {
		return uuid, errors.New("invalid UUID: " + s)
	}
	_, err = hex.Decode(uuid[:], b)
	return
}
