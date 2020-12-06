package ring

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hsson/once"
	"github.com/hsson/ring/store"
	nanoid "github.com/matoous/go-nanoid/v2"
)

const (
	publicKeyIDPrefix = "pub:"

	defaultIDAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	defaultIDLength   = 8
)

// ErrKeyNotFound is returned if trying to find a non-existing or expired key
var ErrKeyNotFound = errors.New("hsson/ring: key not found")

// ErrKeyRotation is returned if a new key could not be created as part of
// replacing an expired signing key
var ErrKeyRotation = errors.New("hsson/ring: could not rotate expired key")

// SigningKey is used to sign new data. It has a corresponding
// verification key which can be used to verify that the data signed
// is valid, identified by ID. The key pair expires at the ExpiresAt
// time. After expired, it can no longer be used to verify data.
type SigningKey struct {
	// ID is a unique identifier for a keypair
	ID string
	// Key is the actual RSA key used for signing data
	Key *rsa.PrivateKey
	// ExpiresAt is when the signing key will be rotated
	ExpiresAt time.Time
}

// Options can be specified to customize the behavior of the Keychain
type Options struct {
	// TTL defines how long signing keys will be active before they are
	// replaced with a new key. The TTL directly defines how long
	// a private key will be kept, while a public key will be kept
	// 2x TTL. Default: 1 hour
	TTL time.Duration

	// KeySize defines the size in bits of the generated keys. Default: 2048
	KeySize int

	// IDAlphabet defines which characters are used to generate key IDs. Default: a...zA...Z
	IDAlphabet string

	// IDLength determines the length of key IDs. Default: 8
	IDLength int
}

var defaultOptions = Options{
	TTL:     1 * time.Hour,
	KeySize: 2048,

	IDAlphabet: defaultIDAlphabet,
	IDLength:   defaultIDLength,
}

// Keychain is used to automatically manage asymmetric keys in a
// secure and easy-to-manage way.
type Keychain interface {
	// SigningKey returns a fresh key which can be used for signing data. The
	// keypair is uniquely identified by an ID.
	SigningKey() (*SigningKey, error)
	// GetVerifier can be used to get the public key for a specific keypair
	// identified by an ID.
	GetVerifier(id string) (*rsa.PublicKey, error)
}

// New creates a new Keychain with a given store used to persist
// generated keys.
func New(store store.Store) Keychain {
	return NewWithOptions(store, defaultOptions)
}

// NewWithOptions creates a new Keychain with a given store used to
// persist generated keys and together with custom options
func NewWithOptions(store store.Store, options Options) Keychain {
	if options.TTL == 0 {
		options.TTL = defaultOptions.TTL
	}

	if options.KeySize == 0 {
		options.KeySize = defaultOptions.KeySize
	}

	if options.IDAlphabet == "" {
		options.IDAlphabet = defaultOptions.IDAlphabet
	}

	if options.IDLength == 0 {
		options.IDLength = defaultOptions.IDLength
	}

	keychain := &ring{
		store:   store,
		options: options,

		rotatehOnce: &once.ValueError{},
	}

	keychain.initialize()
	return keychain
}

type ring struct {
	store   store.Store
	options Options

	currentSigningKey atomic.Value

	rotatehOnce *once.ValueError
}

func (r *ring) initialize() {
	privateKeys, err := r.getNonExpiredPrivateKeysSortedByExpiryDate()
	if err != nil {
		panic(fmt.Errorf("failed to get private keys: %w", err))
	}
	if len(privateKeys) != 0 {
		keyToUse := privateKeys[0]
		untyped, err := x509.ParsePKCS8PrivateKey(keyToUse.Data)
		if err != nil {
			panic(fmt.Errorf("private key data could not be parsed: %w", err))
		}
		privateKey, ok := untyped.(*rsa.PrivateKey)
		if !ok {
			panic(fmt.Errorf("key has invalid type: %w", err))
		}
		signingKey := &SigningKey{
			ID:        keyToUse.ID,
			ExpiresAt: keyToUse.ExpiresAt,
			Key:       privateKey,
		}
		r.currentSigningKey.Store(signingKey)
	} else {
		signingKey, err := r.createNewSigningKey()
		if err != nil {
			panic(fmt.Sprintf("failed to create new signing key: %v", err))
		}

		privateStoreKey, publicStoreKey, err := r.createStoreKeyPairFromSigningKey(signingKey)
		if err != nil {
			panic(fmt.Errorf("failed to create key pair from signing key: %w", err))
		}

		err = r.storeKeyPair(privateStoreKey, publicStoreKey)
		if err != nil {
			panic(fmt.Errorf("failed to store key pair: %w", err))
		}

		r.currentSigningKey.Store(signingKey)
	}
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

func (r *ring) createStoreKeyPairFromSigningKey(signingKey *SigningKey) (store.Key, store.Key, error) {
	publicKeyExpiresAt := signingKey.ExpiresAt.Add(r.options.TTL)

	privateKeyData, err := x509.MarshalPKCS8PrivateKey(signingKey.Key)
	if err != nil {
		return store.Key{}, store.Key{}, err
	}

	privateStoreKey := store.Key{
		ID:        signingKey.ID,
		IsPrivate: true,
		ExpiresAt: signingKey.ExpiresAt,
		Data:      privateKeyData,
	}

	publicKeyData, err := x509.MarshalPKIXPublicKey(&signingKey.Key.PublicKey)
	if err != nil {
		return store.Key{}, store.Key{}, err
	}

	publicStoreKey := store.Key{
		ID:        fmt.Sprintf("%s%s", publicKeyIDPrefix, signingKey.ID),
		IsPrivate: false,
		ExpiresAt: publicKeyExpiresAt,
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

	signingKey := SigningKey{
		ID:        id,
		ExpiresAt: time.Now().Add(r.options.TTL),
		Key:       privateKey,
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

func (r *ring) SigningKey() (*SigningKey, error) {
	val := r.currentSigningKey.Load()
	if val == nil {
		panic("not initialized")
	}
	key, ok := val.(*SigningKey)
	if !ok {
		panic("stored signing key has incorrect type")
	}

	if time.Now().After(key.ExpiresAt) {
		newKey, err := r.rotateSigningKey()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyRotation, err)
		}
		return newKey, nil
	}

	return key, nil
}

func (r *ring) GetVerifier(id string) (*rsa.PublicKey, error) {
	key, err := r.store.Find(fmt.Sprintf("%s%s", publicKeyIDPrefix, id))
	if err != nil {
		return nil, err
	}
	if time.Now().After(key.ExpiresAt) {
		return nil, ErrKeyNotFound
	}

	untyped, err := x509.ParsePKIXPublicKey(key.Data)
	if err != nil {
		return nil, err
	}
	pub, ok := untyped.(*rsa.PublicKey)
	if !ok {
		return nil, ErrKeyNotFound
	}
	return pub, nil
}

func (r *ring) rotateSigningKey() (*SigningKey, error) {
	val, err := r.rotatehOnce.Do(func() (interface{}, error) {
		defer func() {
			r.rotatehOnce = &once.ValueError{}
		}()

		newSigningKey, err := r.createNewSigningKey()
		if err != nil {
			return nil, err
		}

		privateStoreKey, publicStoreKey, err := r.createStoreKeyPairFromSigningKey(newSigningKey)
		if err != nil {
			return nil, err
		}

		if err = r.storeKeyPair(privateStoreKey, publicStoreKey); err != nil {
			return nil, err
		}

		r.currentSigningKey.Store(newSigningKey)
		return newSigningKey, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*SigningKey), nil
}
