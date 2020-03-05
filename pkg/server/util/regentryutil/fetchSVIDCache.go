package regentryutil

import (
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/spiffe/spire/proto/spire/common"
)

type FetchSVIDCache struct {
	cache   *lru.Cache
	timeNow func() time.Time

	mu sync.RWMutex
}

type cacheResult struct {
	entries   []*common.RegistrationEntry
	expiresAt time.Time
}

func NewFetchSVIDCache(cacheSize int) (*FetchSVIDCache, error) {
	cache, err := lru.New(cacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create lru: %v", err)
	}
	return &FetchSVIDCache{
		cache:   cache,
		timeNow: time.Now,
	}, nil
}

func (c *FetchSVIDCache) Get(key string) ([]*common.RegistrationEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ifc, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}
	value, ok := ifc.(*cacheResult)
	if !ok {
		return nil, false
	}
	if c.timeNow().After(value.expiresAt) {
		c.cache.Remove(key)
		return nil, false
	}
	return value.entries, true
}

func (c *FetchSVIDCache) AddWithExpire(key string, value []*common.RegistrationEntry, expire time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Add(key, &cacheResult{
		entries:   value,
		expiresAt: c.timeNow().Add(expire),
	})
}
