package resolve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TURNERO/tenantkit/resolve"
)

type stubResolver struct {
	tenantID string
	ok       bool
	err      error
}

func (s stubResolver) ResolveTenant(ctx context.Context, src resolve.Source) (string, bool, error) {
	return s.tenantID, s.ok, s.err
}

func TestRunChain_FirstMatchWins(t *testing.T) {
	tenantID, err := resolve.RunChain(context.Background(), []resolve.TenantResolver{
		stubResolver{ok: false},
		stubResolver{tenantID: "acme", ok: true},
		stubResolver{tenantID: "should-not-be-reached", ok: true},
	}, fakeSource{})
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if tenantID != "acme" {
		t.Errorf("RunChain tenantID = %q, want acme", tenantID)
	}
}

func TestRunChain_NoResolverMatches(t *testing.T) {
	tenantID, err := resolve.RunChain(context.Background(), []resolve.TenantResolver{
		stubResolver{ok: false},
		stubResolver{ok: false},
	}, fakeSource{})
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if tenantID != "" {
		t.Errorf("RunChain tenantID = %q, want empty", tenantID)
	}
}

func TestRunChain_StopsOnFirstError(t *testing.T) {
	wantErr := errors.New("invalid credential")
	_, err := resolve.RunChain(context.Background(), []resolve.TenantResolver{
		stubResolver{ok: true, err: wantErr},
		stubResolver{tenantID: "should-not-be-reached", ok: true},
	}, fakeSource{})
	if !errors.Is(err, wantErr) {
		t.Errorf("RunChain error = %v, want %v", err, wantErr)
	}
}
