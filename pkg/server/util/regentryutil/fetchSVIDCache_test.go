package regentryutil

import (
	"testing"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

type mockTime struct {
	now time.Time
}

func (m *mockTime) StepForward(d time.Duration) { m.now = m.now.Add(d) }
func (m *mockTime) Now() time.Time              { return m.now }

func TestFetchSVIDCache(t *testing.T) {
	mt := &mockTime{}

	ttl := time.Minute
	cache, err := NewFetchSVIDCache(10)
	require.NoError(t, err)
	cache.timeNow = mt.Now

	key := "spiffe://example.org/root"
	oneID := "spiffe://example.org/1"

	entries := []*common.RegistrationEntry{
		&common.RegistrationEntry{
			ParentId: key,
			SpiffeId: oneID,
		},
	}

	// cache is empty
	val, ok := cache.Get(key)
	require.Empty(t, val)
	require.False(t, ok)

	cache.AddWithExpire(key, entries, ttl)

	// cached value exists
	val, ok = cache.Get(key)
	require.Equal(t, entries, val)
	require.True(t, ok)

	mt.StepForward(ttl - time.Millisecond)

	// cached value still exists after some time
	val, ok = cache.Get(key)
	require.Equal(t, entries, val)
	require.True(t, ok)

	mt.StepForward(2 * time.Millisecond)

	// cached value disappears after TTL
	val, ok = cache.Get(key)
	require.Empty(t, val)
	require.False(t, ok)

	// verify its actually removed from internal cache
	ifc, ok := cache.cache.Get(key)
	require.Nil(t, ifc)
	require.False(t, ok)
}
