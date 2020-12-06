package ring_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/hsson/ring"
	"github.com/hsson/ring/store/inmem"
)

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

func TestListVerifierKeys(t *testing.T) {
	store := inmem.NewInMemoryStore()

	r := ring.NewWithOptions(store, ring.Options{
		RotationFrequency:  200 * time.Millisecond,
		VerificationPeriod: 1 * time.Minute,
	})

	key1, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)

	key4, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	verifiers, err := r.ListVerifiers()
	if err != nil {
		t.Fatal(err)
	}

	if len(verifiers) != 2 {
		t.Errorf("unexpected length, got %v want %v", len(verifiers), 2)
	}

	if verifiers[0].ID != key1.ID {
		t.Errorf("expected first verifier to belong to first key generated, got %v want %v",
			verifiers[0].ID, key1.ID)
	}

	if verifiers[1].ID != key4.ID {
		t.Errorf("expected second verifier to belong to second key generated, got %v want %v",
			verifiers[1].ID, key4.ID)
	}
}

func TestForceRotation(t *testing.T) {
	store := inmem.NewInMemoryStore()

	r := ring.NewWithOptions(store, ring.Options{
		RotationFrequency: 1 * time.Hour,
	})

	key1, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	err = r.Rotate()
	if err != nil {
		t.Fatal(err)
	}

	key2, err := r.SigningKey()
	if err != nil {
		t.Fatal(err)
	}

	if key1.ID == key2.ID {
		t.Error("expected keys to have different ID, was equal")
	}
}

func TestVerifierKeyEncodeToPEM(t *testing.T) {
	expectedPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9UAiPrB5gDIpe3q1Nby0
cGdNEis0AkgrBO9psT+MuqHdPMi8ENUGAhxKVOkmqiOc4pGgkEp3/lxZFXADY5ny
KH2ouvL0w08Qf76o+HoGSBVDb4gMqFaZZ7kHznRtS37rhA5a4eVWzse/5x0mi9Bf
caJqLAFyfZPShmTITwJaiJpiecHxvptnXljC5I71urkMsD5A9p+25uGEDsLHlBEy
4ZzY70Xl/np1hVYgtT60cybb/MGjV9p2HQlbUXA1bIdHlnTlPLFM8A2VOsi1wRP1
Lx7NN5n1F79b6qWIxQhuGIJ0Pg1ehSEKoxvFTi7r34c0lGGBL8Bl7xMZwgn+ovA+
wwIDDf//
-----END PUBLIC KEY-----
`
	pemBlock, _ := pem.Decode([]byte(expectedPEM))
	untyped, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaPublic, ok := untyped.(*rsa.PublicKey)
	if !ok {
		t.Fatal("not rsa public key")
	}
	verifierKey := &ring.VerifierKey{
		ID:        "some id",
		Key:       rsaPublic,
		ExpiresAt: time.Now().Add(5 * time.Hour),
	}

	verifierKeyPEM := verifierKey.EncodeToPEM()
	if string(verifierKeyPEM) != expectedPEM {
		t.Errorf("PEM is not matching, got:\n%v\nwant:\n%v", string(verifierKeyPEM), expectedPEM)
	}
}
