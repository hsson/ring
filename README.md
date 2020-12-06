# hsson/ring

**WORK IN PROGRESS**: This project is not in a production ready state, please await v1.0.0.

[![PkgGoDev](https://pkg.go.dev/badge/github.com/hsson/ring)](https://pkg.go.dev/github.com/hsson/ring) [![GoReportCard](https://goreportcard.com/badge/github.com/hsson/ring)](https://goreportcard.com/report/github.com/hsson/ring)

Automatically rotate signing keys with ease.

## Thread safety
`hsson/ring` is completely thread safe. If using `hsson/ring` in just a single instance of your application, there will only ever be a single signing key active at any given time. However, there are no cross-instance/node synchronization, so if using `hsson/ring` on multiple instances of your application, there might be more than a single signing key active at a given moment, this is however completely fine, it will just add more data in your database.

## Examples
### Example of JWT signing with `dgrijalva/jwt-go`
Below is an example of using `hsson/ring` together with `dgrijalva/jwt-go` to achieve automatic rotation of keys when signing JWT access tokens.

First create an instance of the Ring keychain. Can be done once at the initialization step of your application:
```go
r := ring.New()
```
then sign your JWT:
```go
// Get a signing key from Ring
ringSigningKey, err := r.SigningKey()
if err != nil {
  // ...
}

// Create the token
token := jwt.New(jwt.GetSigningMethod("HS256"))
// Set the Key ID header so we can later get the correct verifier key
token.Header["kid"] = ringSigningKey.ID

// Set JWT expiration time, and cap it to our signing keys max verification time
exp := time.Now().Add(time.Hour * 72)
if exp.After(ringSinginKey.VerifiableUntil) {
  exp = ringSigningKey.VerifiableUntil
}
token.Claims["exp"] = exp.Unix()

// Sign and get the complete encoded token as a string
tokenString, err := token.SignedString(ringSigningKey.Key)
```

### Example of JWT validation with `dgrijalva/jwt-go`
Below is an example of how to verify a JWT previously signed using a key provided by `hsson/ring`.

First create an instance of the Ring keychain. Can be done once at the initialization step of your application. It does not have to be the exact same instance as the one used to sign your JWT, as long as the instances share the same underlying store:
```go
r := ring.New()
```
then in your authentication middleware:
```go
myTokenString := ... // Get from e.g. the Authorization header
token, err := jwt.Parse(myTokenString, func(token *jwt.Token) ([]byte, error) {
  keyID := token.Header["kid"]
  publicKey, err := r.GetVerifier(keyID)
  if err != nil {
    return nil, err
  }
  return publicKey.EncodeToPEM(), nil
})

if err == nil && token.Valid {
  // Success
} else {
  // Invalid token
}
```