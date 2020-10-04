package trojan

import (
	"fmt"
	"sync"
)

// Trojan user
type User struct {
	Hex string
}

func NewUser(password string) *User {
	u := &User{
		Hex: SHA224String(password),
	}
	return u
}

// Trojan user manager
type UserManager struct {
	mux4Users, mux4Hexs sync.RWMutex
	users, hexs         map[string]*User
}

// func (m *UserManager) AuthUser(hash string) (bool, user.User) {
// 	m.mux4Users.RLock()
// 	defer m.mux4Users.RUnlock()
// 	if user, found := m.users[hash]; found {
// 		return true, user
// 	}
// 	return false, nil
// }

func (m *UserManager) AddUser(hash string, more ...string) error {
	m.mux4Users.Lock()
	defer m.mux4Users.Unlock()
	if _, found := m.users[hash]; found {
		return fmt.Errorf("hash %v already exists", hash)
	}
	user := NewUser(hash)
	m.users[hash] = user

	m.mux4Hexs.Lock()
	defer m.mux4Hexs.Unlock()
	m.hexs[user.Hex] = user

	return nil
}

// func (m *UserManager) DelUser(hash string) error {
// 	m.mux4Users.Lock()
// 	defer m.mux4Users.Unlock()
// 	user, found := m.users[hash]
// 	if !found {
// 		return fmt.Errorf("hash %v not found", hash)
// 	}
// 	user.Close()
// 	delete(m.users, hash)

// 	m.mux4Hexs.Lock()
// 	defer m.mux4Hexs.Unlock()
// 	delete(m.hexs, user.Hex)

// 	return nil
// }

// func (m *UserManager) ListUsers() []user.User {
// 	m.mux4Users.RLock()
// 	defer m.mux4Users.RUnlock()
// 	result := make([]user.User, len(m.users))
// 	i := 0
// 	for _, u := range m.users {
// 		result[i] = u
// 		i++
// 	}
// 	return result
// }

func (m *UserManager) CheckHex(hex string) (*User, error) {
	m.mux4Hexs.RLock()
	defer m.mux4Hexs.RUnlock()
	user, found := m.hexs[hex]
	if !found {
		return nil, fmt.Errorf("hex %v not found", hex)
	}
	return user, nil
}

// Create Authenticator from user ids
func NewUserManager(passwords ...string) *UserManager {
	m := &UserManager{
		users: make(map[string]*User),
		hexs:  make(map[string]*User),
	}
	for _, password := range passwords {
		m.AddUser(password)
	}

	// TODO: Load other users from local database

	return m
}
