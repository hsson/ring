package ring

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hsson/once"
	"github.com/hsson/ring/store"
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
// VerifierKey which can be used to verify that the data signed
// is valid, identified by ID.
type SigningKey struct {
	// ID is a unique identifier for a keypair
	ID string
	// Key is the actual RSA key used for signing data
	Key *rsa.PrivateKey
	// RotatedAt is when the signing key will be rotated
	RotatedAt time.Time
	// VerifiableUntil is the time when the public-key equivalent of
	// the signing key will expire, and thus any data signed with it
	// won't be verifiable after this time.
	VerifiableUntil time.Time
}

// VerifierKey is the public part only of a SigningKey
type VerifierKey struct {
	// ID is a unique identifier for a keypair
	ID string
	// Key is the actual RSA public key used for verifying data signature
	Key *rsa.PublicKey
	// ExpiresAt is when this verification key will no longer be usable for
	// verifying data, as it will have been cleared from storage.
	ExpiresAt time.Time
}

// EncodeToPEM encodes the verifier public key in PEM format
func (vk *VerifierKey) EncodeToPEM() []byte {
	bytes, err := x509.MarshalPKIXPublicKey(vk.Key)
	if err != nil {
		panic("failed to marshal public key")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	})
}

// Options can be specified to customize the behavior of the Keychain
type Options struct {
	// RotationFrequency defines how long signing keys will be active
	// before they are replaced with a new key. Default: 1 hour
	RotationFrequency time.Duration

	// VerificationPeriod defines how long data will be able to be verified.
	// After this time, the public key is deleted. Must be longer than
	// RotationFrequency, preferably at least 2x RotationFrequency.
	// Default: RotationFrequency * 2
	VerificationPeriod time.Duration

	// KeySize defines the size in bits of the generated keys. Default: 2048
	KeySize int

	// IDAlphabet defines which characters are used to generate keypair IDs.
	// Does NOT support regex syntax, you must specify all characters.
	// Default: a...zA...Z
	IDAlphabet string

	// IDLength determines the length of keypair IDs. Default: 8
	IDLength int
}

var defaultOptions = Options{
	RotationFrequency:  1 * time.Hour,
	VerificationPeriod: 2 * time.Hour,
	KeySize:            2048,

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
	GetVerifier(id string) (*VerifierKey, error)
	// ListPublicKeys lists all currently active public keys
	ListVerifiers() ([]*VerifierKey, error)
	// Rotate forces a rotation of signing keys
	Rotate() error
}

// New creates a new Keychain with a given store used to persist
// generated keys.
func New(store store.Store) Keychain {
	return NewWithOptions(store, defaultOptions)
}

// NewWithOptions creates a new Keychain with a given store used to
// persist generated keys and together with custom options
func NewWithOptions(store store.Store, options Options) Keychain {
	if options.RotationFrequency == 0 {
		options.RotationFrequency = defaultOptions.RotationFrequency
	}

	if options.VerificationPeriod == 0 {
		options.VerificationPeriod = options.RotationFrequency * 2
	}

	if options.VerificationPeriod < options.RotationFrequency {
		panic("VerificationPeriod must be at >= RotationFrequency")
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
	privateKeys, err := r.getNonExpiredPrivateKeys()
	if err != nil {
		panic(fmt.Errorf("failed to get private keys: %w", err))
	}
	if len(privateKeys) > 0 {
		signingKey, err := r.storedPrivateKeyToSigningKey(privateKeys[0])
		if err != nil {
			panic(err)
		}
		r.currentSigningKey.Store(signingKey)
	} else {
		lock, err := r.store.Lock()
		if err != nil {
			panic(err)
		}
		defer r.store.Unlock(lock)

		existingKeys, err := r.getNonExpiredPrivateKeys()
		if err != nil {
			panic(fmt.Errorf("failed to get private keys: %w", err))
		}
		if len(existingKeys) > 0 {
			// Private key already exists
			signingKey, err := r.storedPrivateKeyToSigningKey(existingKeys[0])
			if err != nil {
				panic(err)
			}
			r.currentSigningKey.Store(signingKey)
		} else {
			signingKey, err := r.createNewSigningKey()
			if err != nil {
				panic(fmt.Sprintf("failed to create new signing key: %v", err))
			}

			privateStoreKey, publicStoreKey, err := createStoreKeyPairFromSigningKey(signingKey)
			if err != nil {
				panic(fmt.Errorf("failed to create key pair from signing key: %w", err))
			}

			if err := r.store.Add(lock, privateStoreKey, publicStoreKey); err != nil {
				panic(fmt.Errorf("failed to store new key pair: %w", err))
			}
			r.currentSigningKey.Store(signingKey)
		}
	}
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

	if time.Now().After(key.RotatedAt) {
		newKey, err := r.rotateSigningKey(true)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyRotation, err)
		}
		return newKey, nil
	}

	return key, nil
}

func (r *ring) GetVerifier(id string) (*VerifierKey, error) {
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
	return &VerifierKey{
		ID:        id,
		Key:       pub,
		ExpiresAt: key.ExpiresAt,
	}, nil
}

func (r *ring) ListVerifiers() ([]*VerifierKey, error) {
	var res []*VerifierKey
	keys, err := r.getNonExpiredPublicKeys()
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		untyped, err := x509.ParsePKIXPublicKey(key.Data)
		if err != nil {
			return nil, err
		}
		pub, ok := untyped.(*rsa.PublicKey)
		if !ok {
			// Should not happen
			return nil, errors.New("stored public key has unknown type")
		}
		res = append(res, &VerifierKey{
			ID:        strings.TrimPrefix(key.ID, publicKeyIDPrefix),
			Key:       pub,
			ExpiresAt: key.ExpiresAt,
		})
	}
	return res, nil
}

func (r *ring) Rotate() error {
	_, err := r.rotateSigningKey(false)
	return err
}

func (r *ring) rotateSigningKey(reuseExisting bool) (*SigningKey, error) {
	val, err := r.rotatehOnce.Do(func() (interface{}, error) {
		defer func() {
			r.rotatehOnce = &once.ValueError{}
		}()

		lock, err := r.store.Lock()
		if err != nil {
			return nil, err
		}
		defer r.store.Unlock(lock)

		if reuseExisting {
			existingKeys, err := r.getNonExpiredPrivateKeys()
			if err != nil {
				return nil, err
			}
			if len(existingKeys) > 0 {
				// Private key already exists
				newSigningKey, err := r.storedPrivateKeyToSigningKey(existingKeys[0])
				if err != nil {
					return nil, err
				}
				r.currentSigningKey.Store(newSigningKey)
				return newSigningKey, nil
			}
		}

		newSigningKey, err := r.createNewSigningKey()
		if err != nil {
			return nil, err
		}

		privateStoreKey, publicStoreKey, err := createStoreKeyPairFromSigningKey(newSigningKey)
		if err != nil {
			return nil, err
		}

		if err := r.store.Add(lock, privateStoreKey, publicStoreKey); err != nil {
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
