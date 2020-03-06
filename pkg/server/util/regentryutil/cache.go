package regentryutil

import (
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/spiffe/spire/proto/spire/common"
)

// FetchRegistrationEntriesCache is a wrapper around LRU cache with expiry, used for caching registration entries of a agent
type FetchRegistrationEntriesCache struct {
	Cache   *lru.Cache
	TimeNow func() time.Time

	mu sync.RWMutex
}

type cacheResult struct {
	entries   []*common.RegistrationEntry
	expiresAt time.Time
}

func NewFetchX509SVIDCache(cacheSize int) (*FetchRegistrationEntriesCache, error) {
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create lru cache: %v", err)
	}
	return &FetchRegistrationEntriesCache{
		Cache:   cache,
		TimeNow: time.Now,
	}, nil
}

func (c *FetchRegistrationEntriesCache) Get(key string) ([]*common.RegistrationEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ifc, ok := c.Cache.Get(key)
	if !ok {
		return nil, false
	}
	value, ok := ifc.(*cacheResult)
	if !ok {
		return nil, false
	}
	if c.TimeNow().After(value.expiresAt) {
		c.Cache.Remove(key)
		return nil, false
	}
	return value.entries, true
}

func (c *FetchRegistrationEntriesCache) AddWithExpire(key string, value []*common.RegistrationEntry, expire time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Cache.Add(key, &cacheResult{
		entries:   value,
		expiresAt: c.TimeNow().Add(expire),
	})
}
