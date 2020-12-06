package ring_test

import (
	"testing"
	"time"

	"github.com/hsson/ring"
	"github.com/hsson/ring/store/inmem"
)

type logger struct {
	t *testing.T
}

func TestSigningKeyRotation(t *testing.T) {
	r := ring.NewWithOptions(inmem.NewInMemoryStore(), ring.Options{
		RotationFrequency: 200 * time.Millisecond,
	})

	keyOne, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	keyTwo, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	keyThree, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	if keyOne.ID == keyTwo.ID {
		t.Errorf("got same id: %v", keyOne.ID)
	}
	if keyOne.ID == keyThree.ID {
		t.Errorf("got same id: %v", keyOne.ID)
	}
	if keyTwo.ID == keyThree.ID {
		t.Errorf("got same id: %v", keyOne.ID)
	}
}

func TestPublicKeyRemains(t *testing.T) {
	r := ring.NewWithOptions(inmem.NewInMemoryStore(), ring.Options{
		RotationFrequency: 200 * time.Millisecond,
	})
	key, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)

	_, err = r.GetVerifier(key.ID)
	if err != nil {
		t.Errorf("could not get verifier")
	}

	time.Sleep(100 * time.Millisecond)
	_, err = r.GetVerifier(key.ID)
	if err == nil {
		t.Errorf("found verifier when expecting it to be expired")
	}
}

func TestShouldReusePreviousKeyIfNotExpired(t *testing.T) {
	store := inmem.NewInMemoryStore()

	r1 := ring.NewWithOptions(store, ring.Options{
		RotationFrequency: 1 * time.Minute,
	})

	key1, err := r1.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	r2 := ring.NewWithOptions(store, ring.Options{
		RotationFrequency: 1 * time.Minute,
	})

	key2, err := r2.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	if key1.ID != key2.ID {
		t.Errorf("got key mismatch, got %v want %v", key2.ID, key1.ID)
	}
}
