package memstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/TURNERO/tenantkit/identity/local/memstore"
	"github.com/TURNERO/tenantkit/identity/local/storetest"
)

func TestMemstoreLoginLimiterConformsToLoginLimiter(t *testing.T) {
	storetest.TestLoginLimiter(t, memstore.NewLoginLimiter(3, time.Hour, time.Hour), 3)
}

// TestLoginLimiter_WindowPrunesOldFailures is memstore-specific: it
// proves failures older than window are pruned and don't count toward
// the threshold. storetest can't assert this generically -- it's
// implementation timing, not part of the interface contract.
func TestLoginLimiter_WindowPrunesOldFailures(t *testing.T) {
	ctx := context.Background()
	limiter := memstore.NewLoginLimiter(3, 50*time.Millisecond, time.Hour)

	if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	time.Sleep(80 * time.Millisecond) // longer than the 50ms window

	// This third failure is real, but the first two are now outside
	// the window and must be pruned -- only 1 failure counts, below
	// the threshold of 3.
	if err := limiter.RecordFailure(ctx, "acme", "alice"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	allowed, err := limiter.Allow(ctx, "acme", "alice")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed -- stale failures should have been pruned")
	}
}

// TestLoginLimiter_FailuresAccumulateAcrossTime proves a sliding
// window correctly accumulates failures spread over time within the
// window, rather than resetting them -- the property a fixed window
// would get wrong at a clock-aligned boundary.
func TestLoginLimiter_FailuresAccumulateAcrossTime(t *testing.T) {
	ctx := context.Background()
	limiter := memstore.NewLoginLimiter(3, 200*time.Millisecond, time.Hour)

	if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // well within the 200ms window

	if err := limiter.RecordFailure(ctx, "acme", "bob"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	allowed, err := limiter.Allow(ctx, "acme", "bob")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if allowed {
		t.Fatal("expected locked out -- all 3 failures fall within the window")
	}
}
