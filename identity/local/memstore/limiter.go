package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/TURNERO/tenantkit/identity/local"
)

// LoginLimiter is an in-memory reference implementation of
// local.LoginLimiter: a sliding-window failure count per (tenantID,
// username). Not a production backend -- see package doc.
type LoginLimiter struct {
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	lockout     time.Duration
	records     map[limiterKey]*limiterRecord
}

type limiterKey struct {
	tenantID string
	username string
}

// limiterRecord tracks recent failures (pruned to the last window on
// every RecordFailure) and, once maxAttempts is reached, the time the
// lockout lifts. lockedUntil is independent of window: an account
// doesn't unlock early just because old failures aged out of the
// counting window.
type limiterRecord struct {
	failures    []time.Time
	lockedUntil time.Time
}

// NewLoginLimiter returns a LoginLimiter that locks an account out for
// lockout after maxAttempts failures within a sliding window of
// duration window (see the design spec's "Design decisions" for why
// sliding rather than fixed).
func NewLoginLimiter(maxAttempts int, window, lockout time.Duration) *LoginLimiter {
	return &LoginLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		lockout:     lockout,
		records:     make(map[limiterKey]*limiterRecord),
	}
}

var _ local.LoginLimiter = (*LoginLimiter)(nil)

func (l *LoginLimiter) Allow(ctx context.Context, tenantID, username string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.records[limiterKey{tenantID, username}]
	if !ok {
		return true, nil
	}
	return time.Now().After(rec.lockedUntil), nil
}

func (l *LoginLimiter) RecordFailure(ctx context.Context, tenantID, username string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := limiterKey{tenantID, username}
	rec, ok := l.records[key]
	if !ok {
		rec = &limiterRecord{}
		l.records[key] = rec
	}

	now := time.Now()
	rec.failures = append(rec.failures, now)

	cutoff := now.Add(-l.window)
	pruned := rec.failures[:0]
	for _, t := range rec.failures {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	rec.failures = pruned

	if len(rec.failures) >= l.maxAttempts {
		rec.lockedUntil = now.Add(l.lockout)
	}
	return nil
}

func (l *LoginLimiter) RecordSuccess(ctx context.Context, tenantID, username string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, limiterKey{tenantID, username})
	return nil
}
