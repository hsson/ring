package store

import (
	"errors"
	"sort"
	"time"
)

var (
	// ErrKeyIDConflict is returned if trying to add a key to the store
	// with an occupied ID.
	ErrKeyIDConflict = errors.New("hsson/ring: key id conflict")

	// ErrInvalidLock is returned if trying to store a key
	// with an expired or non-existing LockToken
	ErrInvalidLock = errors.New("hsson/ring: invalid lock")

	// ErrLockOccupied is returned if trying to get a lock that is
	// already occupied.
	ErrLockOccupied = errors.New("hsson/ring: lock occupied")
)

// LockToken represents a unique identifier for a distributed lock
type LockToken string

// NilLock represents the zero-value of a LockToken
var NilLock LockToken = LockToken("")

// Key is a simple representation of either a private or a public key
// used in cryptography.
type Key struct {
	ID        string
	IsPrivate bool
	ExpiresAt time.Time
	Data      []byte
}

// KeyList is a slice of Key
type KeyList []Key

// SortByExpiresAt sorts a list of keys by expiry date
func (kl KeyList) SortByExpiresAt() {
	sort.Slice(kl, func(i, j int) bool {
		return kl[i].ExpiresAt.Before(kl[j].ExpiresAt)
	})
}

// Store persists keys for the keychain
type Store interface {
	// Add a key into the store. If the store natively supports TTL
	// (such as Redis), the key can safely be set to expire on the time
	// specified by the key's ExpiresAt property. If there is an ID
	// conflict, the ErrKeyIDConflict error should be returned. If
	// the provided LockToken is invalid, ErrInvalidLock should be
	// returned.
	Add(lock LockToken, keys ...Key) error

	// Find returns a previously saved key, indentifed by the provided id.
	// If the key is not found, the ring.ErrKeyNotFound should be returned
	Find(id string) (Key, error)

	// Delete removes the key with the specified identifier from the
	// store. If a key with the specified identifier does not exist, it
	// should NOT give an error.
	Delete(id string) error

	// List returns all currently stored keys.
	List() (KeyList, error)

	// Lock will attempt to acquire a lock used for storing data. If the lock
	// can not be acuired because the lock is occupied, Lock() should immediately
	// return with a ErrLockOccupied error. If successfully getting a lock,
	// it should be unlocked immediately after being done with it. The lock
	// will expire if too long time elapses before unlocking.
	Lock() (LockToken, error)

	// Unlock will unlock a locked lock, given its unique token. If the lock
	// identified by the token is already unlocked, no error is returned.
	Unlock(lock LockToken) error
}
