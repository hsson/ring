package ring

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/hsson/ring/store"
	nanoid "github.com/matoous/go-nanoid/v2"
)

func createStoreKeyPairFromSigningKey(signingKey *SigningKey) (store.Key, store.Key, error) {
	privateKeyData, err := x509.MarshalPKCS8PrivateKey(signingKey.Key)
	if err != nil {
		return store.Key{}, store.Key{}, err
	}

	privateStoreKey := store.Key{
		ID:        signingKey.ID,
		IsPrivate: true,
		ExpiresAt: signingKey.RotatedAt,
		Data:      privateKeyData,
	}

	publicKeyData, err := x509.MarshalPKIXPublicKey(&signingKey.Key.PublicKey)
	if err != nil {
		return store.Key{}, store.Key{}, err
	}

	publicStoreKey := store.Key{
		ID:        fmt.Sprintf("%s%s", publicKeyIDPrefix, signingKey.ID),
		IsPrivate: false,
		ExpiresAt: signingKey.VerifiableUntil,
		Data:      publicKeyData,
	}

	return privateStoreKey, publicStoreKey, nil
}

func (r *ring) createNewSigningKey() (*SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, r.options.KeySize)
	if err != nil {
		return nil, err
	}

	id, err := nanoid.Generate(r.options.IDAlphabet, r.options.IDLength)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	signingKey := SigningKey{
		ID:              id,
		RotatedAt:       now.Add(r.options.RotationFrequency),
		VerifiableUntil: now.Add(r.options.VerificationPeriod),
		Key:             privateKey,
	}
	return &signingKey, nil
}

func (r *ring) getNonExpiredPrivateKeys() (store.KeyList, error) {
	return r.getNonExpiredKeys(true)
}

func (r *ring) getNonExpiredPublicKeys() (store.KeyList, error) {
	return r.getNonExpiredKeys(false)
}

func (r *ring) getNonExpiredKeys(private bool) (store.KeyList, error) {
	allKeys, err := r.store.List()
	if err != nil {
		return store.KeyList{}, err
	}
	var allPrivateOrPublicKeys store.KeyList
	now := time.Now()
	for _, key := range allKeys {
		if key.IsPrivate == private && key.ExpiresAt.After(now) {
			allPrivateOrPublicKeys = append(allPrivateOrPublicKeys, key)
		}
	}

	allPrivateOrPublicKeys.SortByExpiresAt()
	return allPrivateOrPublicKeys, nil
}

func (r *ring) storedPrivateKeyToSigningKey(storedKey store.Key) (*SigningKey, error) {
	untyped, err := x509.ParsePKCS8PrivateKey(storedKey.Data)
	if err != nil {
		return nil, fmt.Errorf("private key data could not be parsed: %w", err)
	}
	privateKey, ok := untyped.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key has invalid type: %w", err)
	}
	signingKey := &SigningKey{
		ID:              storedKey.ID,
		RotatedAt:       storedKey.ExpiresAt,
		VerifiableUntil: storedKey.ExpiresAt.Add(r.options.VerificationPeriod).Add(-r.options.RotationFrequency),
		Key:             privateKey,
	}
	return signingKey, nil
}
