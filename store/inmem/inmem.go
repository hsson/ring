package inmem

import (
	"sync"
	"time"

	nanoid "github.com/matoous/go-nanoid/v2"

	"github.com/hsson/ring"
	"github.com/hsson/ring/store"
)

// NewInMemoryStore creates a new in-memory storage
// container which can be used with the ring keychain.
func NewInMemoryStore() store.Store {
	store := &inmemStore{
		data: make(map[string]store.Key),
	}
	ticker := time.NewTicker(5 * time.Minute)
	go checkForTTL(ticker, store)
	return store
}

type inmemStore struct {
	m sync.RWMutex

	currentLockToken *store.LockToken
	currentLockMutex sync.RWMutex
	data             map[string]store.Key
}

func (s *inmemStore) copy(key store.Key) store.Key {
	return store.Key{
		ID:        key.ID,
		IsPrivate: key.IsPrivate,
		ExpiresAt: key.ExpiresAt,
		Data:      key.Data,
	}
}

func (s *inmemStore) Add(lock store.LockToken, keys ...store.Key) error {
	s.currentLockMutex.RLock()
	defer s.currentLockMutex.RUnlock()

	if s.currentLockToken != nil && *s.currentLockToken != lock {
		return store.ErrInvalidLock
	}

	s.m.Lock()
	defer s.m.Unlock()

	// First check so no ID is conflicting
	for _, key := range keys {
		if _, exists := s.data[key.ID]; exists {
			return store.ErrKeyIDConflict
		}
	}
	// Then actually save them
	for _, key := range keys {
		s.data[key.ID] = s.copy(key)
	}

	return nil
}

func (s *inmemStore) Find(id string) (store.Key, error) {
	s.m.RLock()
	defer s.m.RUnlock()

	key, exists := s.data[id]
	if !exists {
		return store.Key{}, ring.ErrKeyNotFound
	}
	return s.copy(key), nil
}

func (s *inmemStore) Delete(id string) error {
	s.m.Lock()
	defer s.m.Unlock()
	delete(s.data, id)
	return nil
}

func (s *inmemStore) List() (store.KeyList, error) {
	s.m.RLock()
	defer s.m.RUnlock()
	all := make(store.KeyList, len(s.data))
	i := 0
	for _, k := range s.data {
		all[i] = s.copy(k)
		i++
	}
	return all, nil
}

func (s *inmemStore) Lock() (store.LockToken, error) {
	s.currentLockMutex.RLock()
	if s.currentLockToken != nil {
		s.currentLockMutex.RUnlock()
		return store.NilLock, store.ErrLockOccupied
	}
	s.currentLockMutex.RUnlock()
	s.currentLockMutex.Lock()
	defer s.currentLockMutex.Unlock()
	if s.currentLockToken != nil {
		return store.NilLock, store.ErrLockOccupied
	}
	lock := store.LockToken(nanoid.Must(32))
	s.currentLockToken = &lock
	return lock, nil
}

func (s *inmemStore) Unlock(lock store.LockToken) error {
	s.currentLockMutex.RLock()
	if s.currentLockToken == nil || *s.currentLockToken != lock {
		s.currentLockMutex.RUnlock()
		return nil
	}
	s.currentLockMutex.RUnlock()
	s.currentLockMutex.Lock()
	defer s.currentLockMutex.Unlock()
	s.currentLockToken = nil
	return nil
}
