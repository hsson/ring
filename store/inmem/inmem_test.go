package inmem_test

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hsson/ring"
	"github.com/hsson/ring/store"
	"github.com/hsson/ring/store/inmem"
)

func dummyKey() store.Key {
	return store.Key{
		ID:        fmt.Sprintf("key-%d", rand.Int()),
		IsPrivate: rand.Int()%2 == 0,
		ExpiresAt: time.Now().Add(10 * time.Second),
		Data:      []byte{},
	}
}

func getStore() store.Store {
	return inmem.NewInMemoryStore()
}

func TestHandlesTTL(t *testing.T) {
	if getStore().HandlesTTL() {
		t.Errorf("did not expect store to handle TTL")
	}
}

func TestAddAndFind(t *testing.T) {
	s := getStore()

	k := dummyKey()
	s.Add(k)

	sk, err := s.Find(k.ID)
	if err != nil {
		t.Error(err)
	}

	if sk.ID != k.ID {
		t.Errorf("got key %v want %v", sk.ID, k.ID)
	}

	if sk.IsPrivate != k.IsPrivate {
		t.Errorf("got isPrivate %v want %v", sk.IsPrivate, k.IsPrivate)
	}

	if sk.ExpiresAt != k.ExpiresAt {
		t.Errorf("got ExpiresAt %v want %v", sk.ExpiresAt, k.ExpiresAt)
	}
}

func TestFindingNonExisting(t *testing.T) {
	s := getStore()

	_, err := s.Find("non-existing")
	if err == nil {
		t.Errorf("expected error, did not get one")
	}

	if !errors.Is(err, ring.ErrKeyNotFound) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAddConflict(t *testing.T) {
	s := getStore()

	k := dummyKey()
	err := s.Add(k)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = s.Add(k)
	if err == nil {
		t.Errorf("expected error, did not get one")
	}

	if !errors.Is(err, store.ErrKeyIDConflict) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeleteKey(t *testing.T) {
	s := getStore()

	k := dummyKey()
	err := s.Add(k)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = s.Delete(k.ID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = s.Find(k.ID)
	if err == nil {
		t.Errorf("expected error, did not get one")
	}
	if !errors.Is(err, ring.ErrKeyNotFound) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListKeys(t *testing.T) {
	s := getStore()

	k1 := dummyKey()
	k2 := dummyKey()
	k3 := dummyKey()

	if err := s.Add(k1); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := s.Add(k2); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := s.Add(k3); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	keys, err := s.List()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	foundK1 := false
	for _, key := range keys {
		if key.ID == k1.ID {
			foundK1 = true
			break
		}
	}
	if !foundK1 {
		t.Errorf("did not find key 1 in list")
	}

	foundK2 := false
	for _, key := range keys {
		if key.ID == k2.ID {
			foundK2 = true
			break
		}
	}
	if !foundK2 {
		t.Errorf("did not find key 2 in list")
	}

	foundK3 := false
	for _, key := range keys {
		if key.ID == k3.ID {
			foundK3 = true
			break
		}
	}
	if !foundK3 {
		t.Errorf("did not find key 3 in list")
	}
}
