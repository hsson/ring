package inmem

import (
	"sync"
	"time"

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
	sync.RWMutex

	data map[string]store.Key
}

func (s *inmemStore) copy(key store.Key) store.Key {
	return store.Key{
		ID:        key.ID,
		IsPrivate: key.IsPrivate,
		ExpiresAt: key.ExpiresAt,
		Data:      key.Data,
	}
}

func (s *inmemStore) Add(key store.Key) error {
	s.Lock()
	defer s.Unlock()
	if _, exists := s.data[key.ID]; exists {
		return store.ErrKeyIDConflict
	}
	s.data[key.ID] = s.copy(key)
	return nil
}

func (s *inmemStore) Find(id string) (store.Key, error) {
	s.RLock()
	defer s.RUnlock()

	key, exists := s.data[id]
	if !exists {
		return store.Key{}, ring.ErrKeyNotFound
	}
	return s.copy(key), nil
}

func (s *inmemStore) Delete(id string) error {
	s.Lock()
	defer s.Unlock()
	delete(s.data, id)
	return nil
}

func (s *inmemStore) List() (store.KeyList, error) {
	s.RLock()
	defer s.RUnlock()
	all := make(store.KeyList, len(s.data))
	i := 0
	for _, k := range s.data {
		all[i] = s.copy(k)
		i++
	}
	return all, nil
}
