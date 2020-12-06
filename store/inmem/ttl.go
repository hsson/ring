package inmem

import (
	"time"
)

func checkForTTL(ticker *time.Ticker, store *inmemStore) {
	for {
		<-ticker.C
		now := time.Now()
		// The inmem store can not actually return error from List
		keys, _ := store.List()
		for _, key := range keys {
			if now.After(key.ExpiresAt) {
				// The inmem store can not actually return error from Delete
				store.Delete(key.ID)
			}
		}
	}
}
