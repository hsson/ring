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

func (r *ring) storeKeyPair(privateKey, publicKey store.Key) error {
	if err := r.store.Add(privateKey); err != nil {
		return err
	}
	if err := r.store.Add(publicKey); err != nil {
		return err
	}
	return nil
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

func (r *ring) getNonExpiredPrivateKeysSortedByExpiryDate() (store.KeyList, error) {
	allKeys, err := r.store.List()
	if err != nil {
		return store.KeyList{}, err
	}
	var allPrivateKeys store.KeyList
	now := time.Now()
	for _, key := range allKeys {
		if key.IsPrivate && key.ExpiresAt.After(now) {
			allPrivateKeys = append(allPrivateKeys, key)
		}
	}

	allPrivateKeys.SortByExpiresAt()
	return allPrivateKeys, nil
}
