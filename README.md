# hsson/ring

**WORK IN PROGRESS**: This project is not in a production ready state, please await v1.0.0.

[![PkgGoDev](https://pkg.go.dev/badge/github.com/hsson/ring)](https://pkg.go.dev/github.com/hsson/ring) [![GoReportCard](https://goreportcard.com/badge/github.com/hsson/ring)](https://goreportcard.com/report/github.com/hsson/ring)

Automatically rotate signing keys with ease.

## Thread safety
`hsson/ring` is completely thread safe. If using `hsson/ring` in just a single instance of your application, there will only ever be a single signing key active at any given time. However, there are no cross-instance/node synchronization, so if using `hsson/ring` on multiple instances of your application, there might be more than a single signing key active at a given moment, this is however completely fine, it will just add more data in your database.