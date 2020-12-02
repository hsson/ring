package ring

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

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

// SigningKey is used to sign new data. It has a corresponding
// verification key which can be used to verify that the data signed
// is valid, identified by ID. The key pair expires at the ExpiresAt
// time. After expired, it can no longer be used to verify data.
type SigningKey struct {
	ID        string
	Key       *rsa.PrivateKey
	ExpiresAt time.Time
}

// ErrorLogger abstracts a generic logger which ring will use to
// log eventual non criticial errors to
type ErrorLogger interface {
	Errorf(format string, values ...interface{})
}

// Options can be specified to customize the behavior of the Keychain
type Options struct {
	// TTL defines how long signing keys will be active before they are
	// replaced with a new key. The TTL directly defines how long
	// a private key will be kept, while a public key will be kept
	// 2x TTL.
	TTL time.Duration

	// CheckInterval defines how often the the TTL of keys should be checked.
	// Defaults to TTL/2.
	CheckInterval time.Duration

	// KeySize defines the size in bits of the generated keys
	KeySize int

	// ErrorLogger is used to log errors
	ErrorLogger ErrorLogger

	// IDAlphabet defines which characters are used to generate key IDs
	IDAlphabet string

	// IDLength determines the length of key IDs
	IDLength int
}

var defaultOptions = Options{
	TTL:           1 * time.Hour,
	CheckInterval: 30 * time.Minute,
	KeySize:       2048,

	ErrorLogger: nil,

	IDAlphabet: defaultIDAlphabet,
	IDLength:   defaultIDLength,
}

// Keychain is used to automatically manage asymmetric keys in a
// secure and easy-to-manage way.
type Keychain interface {
	SigningKey() *SigningKey
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

	if options.CheckInterval == 0 {
		options.CheckInterval = options.TTL / 2
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

	if options.ErrorLogger == nil {
		options.ErrorLogger = defaultOptions.ErrorLogger
	}

	keychain := &ring{
		store:   store,
		options: options,
	}

	if !store.HandlesTTL() {
		ticker := time.NewTicker(options.CheckInterval)
		go periodicCheck(ticker, keychain)
	}

	keychain.initialize()
	return keychain
}

func periodicCheck(ticker *time.Ticker, r *ring) {
	for {
		<-ticker.C
		now := time.Now()
		keys, err := r.store.List()
		if err != nil {
			r.errorf("could not list keys when doing periodic TTL check: %v", err)
			continue
		}
		for _, key := range keys {
			if now.After(key.ExpiresAt) {
				if err := r.store.Delete(key.ID); err != nil {
					if !errors.Is(err, ErrKeyNotFound) {
						r.errorf("got unknown error when trying to delete expired key: %v", err)
					}
				}
			}
		}
	}
}

type ring struct {
	store   store.Store
	options Options

	currentSigningKey atomic.Value
}

func (r *ring) errorf(format string, values ...interface{}) {
	if r.options.ErrorLogger != nil {
		r.options.ErrorLogger.Errorf(format, values)
	}
}

func (r *ring) initialize() {
	privateKeys, err := r.getNonExpiredPrivateKeysSortedByExpiryDate()
	if err != nil {
		panicerr("failed to get private keys", err)
	}
	if len(privateKeys) != 0 {
		keyToUse := privateKeys[0]
		untyped, err := x509.ParsePKCS8PrivateKey(keyToUse.Data)
		if err != nil {
			panicerr("private key data could not be parsed", err)
		}
		privateKey, ok := untyped.(*rsa.PrivateKey)
		if !ok {
			panicerr("key has invalid type", err)
		}
		signingKey := &SigningKey{
			ID:        keyToUse.ID,
			ExpiresAt: keyToUse.ExpiresAt,
			Key:       privateKey,
		}
		r.currentSigningKey.Store(signingKey)
		go r.scheduleSigningKeyRefresh(signingKey)
	} else {
		signingKey, err := r.createNewSigningKey()
		if err != nil {
			panic(fmt.Sprintf("failed to create new signing key: %v", err))
		}

		privateStoreKey, publicStoreKey, err := r.createStoreKeyPairFromSigningKey(signingKey)
		if err != nil {
			panicerr("failed to create key pair from signing key", err)
		}

		err = r.storeKeyPair(privateStoreKey, publicStoreKey)
		if err != nil {
			panicerr("failed to store key pair", err)
		}

		r.currentSigningKey.Store(signingKey)
		go r.scheduleSigningKeyRefresh(signingKey)
	}
}

func (r *ring) storeKeyPair(privateKey, publicKey store.Key) error {
	var err error
	var wg sync.WaitGroup

	store := func(key store.Key) {
		e := r.store.Add(key)
		if err != nil {
			err = e
		}
		wg.Done()
	}
	wg.Add(2)
	go store(privateKey)
	go store(publicKey)
	wg.Wait()

	return err
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

func (r *ring) scheduleSigningKeyRefresh(key *SigningKey) {
	newSigningKey, err := r.createNewSigningKey()
	if err != nil {
		r.errorf("failed to generate a new signing key: %v", err)
		// retry again after 5 seconds
		time.AfterFunc(5*time.Second, func() {
			r.scheduleSigningKeyRefresh(key)
		})
		return
	}
	privateStoreKey, publicStoreKey, err := r.createStoreKeyPairFromSigningKey(newSigningKey)
	if err != nil {
		r.errorf("failed to create key pair from new signing key: %v", err)
		// retry again after 5 seconds
		time.AfterFunc(5*time.Second, func() {
			r.scheduleSigningKeyRefresh(key)
		})
		return
	}

	if err = r.storeKeyPair(privateStoreKey, publicStoreKey); err != nil {
		r.errorf("failed to store key pair: %v", err)
		// retry again after 5 seconds
		time.AfterFunc(5*time.Second, func() {
			r.scheduleSigningKeyRefresh(key)
		})
		return
	}

	time.AfterFunc(key.ExpiresAt.Sub(time.Now()), func() {
		r.currentSigningKey.Store(newSigningKey)
		if err = r.store.Delete(key.ID); err != nil {
			r.errorf("failed to delete old signing private key")
		}
		go r.scheduleSigningKeyRefresh(newSigningKey)
	})
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

func (r *ring) SigningKey() *SigningKey {
	val := r.currentSigningKey.Load()
	if val == nil {
		panic("not initialized")
	}
	key, ok := val.(*SigningKey)
	if !ok {
		panic("stored signing key has incorrect type")
	}
	return key
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

func panicerr(msg string, err error) {
	panic(fmt.Sprintf("%s: %v", msg, err))
}
