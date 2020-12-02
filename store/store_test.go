package store_test

import (
	"testing"
	"time"

	"github.com/hsson/ring/store"
)

func TestSortKeyListByExpiresAt(t *testing.T) {
	first := store.Key{ID: "first", ExpiresAt: time.Now()}
	second := store.Key{ID: "second", ExpiresAt: time.Now().Add(5 * time.Second)}
	third := store.Key{ID: "third", ExpiresAt: time.Now().Add(15 * time.Second)}

	kl := store.KeyList{third, first, second}

	kl.SortByExpiresAt()

	if kl[0].ID != first.ID {
		t.Errorf("expected first item to be %v was %v", first.ID, kl[0].ID)
	}

	if kl[1].ID != second.ID {
		t.Errorf("expected second item to be %v was %v", second.ID, kl[1].ID)
	}

	if kl[2].ID != third.ID {
		t.Errorf("expected third item to be %v was %v", third.ID, kl[2].ID)
	}
}
