package ring_test

import (
	"log"
	"testing"
	"time"

	"github.com/hsson/ring"
	"github.com/hsson/ring/store/inmem"
)

type logger struct {
}

func (l *logger) Errorf(format string, values ...interface{}) {
	log.Printf(format, values...)
}

func TestSigningKeyRotation(t *testing.T) {
	r := ring.NewWithOptions(inmem.NewInMemoryStore(), ring.Options{
		TTL:         2 * time.Second,
		ErrorLogger: &logger{},
	})

	keyOne := r.SigningKey()
	time.Sleep(3 * time.Second)
	keyTwo := r.SigningKey()

	if keyOne.ID == keyTwo.ID {
		t.Errorf("got same id: %v", keyOne.ID)
	}
}

func TestPublicKeyRemains(t *testing.T) {
	r := ring.NewWithOptions(inmem.NewInMemoryStore(), ring.Options{
		TTL:         3 * time.Second,
		ErrorLogger: &logger{},
	})
	key := r.SigningKey()
	time.Sleep(4 * time.Second)

	_, err := r.GetVerifier(key.ID)
	if err != nil {
		t.Errorf("could not get verifier")
	}

	time.Sleep(2 * time.Second)
	_, err = r.GetVerifier(key.ID)
	if err == nil {
		t.Errorf("found verifier when expecting it to be expired")
	}
}

func TestShouldReusePreviousKeyIfNotExpired(t *testing.T) {
	store := inmem.NewInMemoryStore()

	r1 := ring.NewWithOptions(store, ring.Options{
		TTL:         1 * time.Minute,
		ErrorLogger: &logger{},
	})

	key1 := r1.SigningKey()

	r2 := ring.NewWithOptions(store, ring.Options{
		TTL:         1 * time.Minute,
		ErrorLogger: &logger{},
	})

	key2 := r2.SigningKey()

	if key1.ID != key2.ID {
		t.Errorf("got key mismatch, got %v want %v", key2.ID, key1.ID)
	}
}
