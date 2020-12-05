package ring

import (
	"sync"
	"sync/atomic"
)

type onceErr struct {
	m      sync.Mutex
	done   uint32
	result error
}

// Do runs the specified function only once, but
// all callers gets the same result from that one run.
// Inspired by: https://golang.org/pkg/sync/#Once
func (o *onceErr) do(f func() error) error {
	if atomic.LoadUint32(&o.done) == 1 {
		return o.result
	}

	o.m.Lock()
	defer o.m.Unlock()
	if o.done == 0 {
		defer atomic.StoreUint32(&o.done, 1)
		o.result = f()
	}
	return o.result
}
