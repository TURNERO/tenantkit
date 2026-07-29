package grpcmw_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/grpcmw"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
	"github.com/TURNERO/tenantkit/store/memstore"
)

type fakeResolver struct {
	tenantID string
	ok       bool
	err      error
}

func (f fakeResolver) ResolveTenant(ctx context.Context, src resolve.Source) (string, bool, error) {
	return f.tenantID, f.ok, f.err
}

type fakeIdentityProvider struct {
	identity *tenantkit.Identity
	err      error
}

func (f fakeIdentityProvider) Authenticate(ctx context.Context, src resolve.Source) (*tenantkit.Identity, error) {
	return f.identity, f.err
}

func newTestTenantStore(t *testing.T, tenantID string, active bool) store.TenantStore {
	t.Helper()
	s := memstore.New()
	if err := s.CreateTenant(context.Background(), &tenantkit.Tenant{ID: tenantID, DisplayName: tenantID, Active: active}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return s
}

func TestUnaryServerInterceptor_ResolvesTenantAndCallsHandler(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})

	var gotTenant *tenantkit.Tenant
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		gotTenant, _ = tenantkit.TenantFromContext(ctx)
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want ok", resp)
	}
	if gotTenant == nil || gotTenant.ID != "acme" {
		t.Errorf("TenantFromContext = %+v, want ID acme", gotTenant)
	}
}

func TestUnaryServerInterceptor_NoCredentialsRejectedWithUnauthenticated(t *testing.T) {
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryServerInterceptor_InvalidCredentialsRejectedWithUnauthenticated(t *testing.T) {
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("bad key")}},
		TenantStore: memstore.New(),
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryServerInterceptor_IdentityAuthenticateErrorRejectedWithUnauthenticated(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{err: errors.New("invalid token")},
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryServerInterceptor_InactiveTenantRejectedWithPermissionDenied(t *testing.T) {
	ts := newTestTenantStore(t, "acme", false)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestUnaryServerInterceptor_IdentityTenantMismatchRejectedWithPermissionDenied(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: &tenantkit.Identity{UserID: "u1", TenantID: "globex"}},
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestUnaryServerInterceptor_IdentityPopulatedWhenTenantsMatch(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:        []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore:      ts,
		IdentityProvider: fakeIdentityProvider{identity: &tenantkit.Identity{UserID: "u1", TenantID: "acme"}},
	})

	var gotIdentity *tenantkit.Identity
	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		gotIdentity, _ = tenantkit.IdentityFromContext(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if gotIdentity == nil || gotIdentity.UserID != "u1" {
		t.Errorf("IdentityFromContext = %+v, want UserID u1", gotIdentity)
	}
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func TestStreamServerInterceptor_ResolvesTenantAndCallsHandler(t *testing.T) {
	ts := newTestTenantStore(t, "acme", true)
	interceptor := grpcmw.StreamServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{tenantID: "acme", ok: true}},
		TenantStore: ts,
	})

	var gotTenant *tenantkit.Tenant
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		gotTenant, _ = tenantkit.TenantFromContext(ss.Context())
		return nil
	}

	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{}, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if gotTenant == nil || gotTenant.ID != "acme" {
		t.Errorf("TenantFromContext = %+v, want ID acme", gotTenant)
	}
}

func TestStreamServerInterceptor_NoCredentialsRejectedWithUnauthenticated(t *testing.T) {
	interceptor := grpcmw.StreamServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
	})

	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{}, func(srv interface{}, ss grpc.ServerStream) error {
		t.Fatal("handler should not be called")
		return nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("status code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryServerInterceptor_DefaultErrorHandlerExposesUnderlyingError(t *testing.T) {
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("backend store unreachable: dial tcp 10.0.0.5:5432")}},
		TenantStore: memstore.New(),
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	// Default behavior is unchanged from before ErrorHandler existed: the
	// underlying error's text reaches the client verbatim.
	if got := status.Convert(err).Message(); got != "backend store unreachable: dial tcp 10.0.0.5:5432" {
		t.Errorf("status message = %q, want the underlying error text verbatim", got)
	}
}

func TestUnaryServerInterceptor_CustomErrorHandlerRedactsUnderlyingError(t *testing.T) {
	var gotCode codes.Code
	var gotErr error
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("backend store unreachable: dial tcp 10.0.0.5:5432")}},
		TenantStore: memstore.New(),
		ErrorHandler: func(code codes.Code, err error) error {
			gotCode, gotErr = code, err
			return status.Error(code, "internal error")
		},
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if got := status.Convert(err).Message(); got != "internal error" {
		t.Errorf("status message = %q, want the custom handler's redacted message", got)
	}
	if gotCode != codes.Unauthenticated {
		t.Errorf("ErrorHandler code = %v, want Unauthenticated", gotCode)
	}
	if gotErr == nil || gotErr.Error() != "backend store unreachable: dial tcp 10.0.0.5:5432" {
		t.Errorf("ErrorHandler err = %v, want the underlying error verbatim", gotErr)
	}
}

func TestUnaryServerInterceptor_CustomErrorHandlerCalledForSentinelErrors(t *testing.T) {
	var gotErr error
	interceptor := grpcmw.UnaryServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: false}},
		TenantStore: memstore.New(),
		ErrorHandler: func(code codes.Code, err error) error {
			gotErr = err
			return status.Error(code, "no")
		},
	})

	_, err := interceptor(context.Background(), "req", &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	// The "no credentials presented" rejection is grpcmw's own sentinel,
	// not an underlying resolver/store error -- ErrorHandler must still
	// see it, so a custom handler can uniformly log or reshape every
	// rejection, not just ones wrapping external errors.
	if gotErr == nil || gotErr.Error() != "grpcmw: no credentials presented" {
		t.Errorf("ErrorHandler err = %v, want the no-credentials sentinel", gotErr)
	}
	if got := status.Convert(err).Message(); got != "no" {
		t.Errorf("status message = %q, want the custom handler's message", got)
	}
}

func TestStreamServerInterceptor_CustomErrorHandlerRedactsUnderlyingError(t *testing.T) {
	interceptor := grpcmw.StreamServerInterceptor(grpcmw.Config{
		Resolvers:   []resolve.TenantResolver{fakeResolver{ok: true, err: errors.New("backend store unreachable")}},
		TenantStore: memstore.New(),
		ErrorHandler: func(code codes.Code, err error) error {
			return status.Error(code, "internal error")
		},
	})

	err := interceptor(nil, &fakeServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{}, func(srv interface{}, ss grpc.ServerStream) error {
		t.Fatal("handler should not be called")
		return nil
	})
	if got := status.Convert(err).Message(); got != "internal error" {
		t.Errorf("status message = %q, want the custom handler's redacted message", got)
	}
}
