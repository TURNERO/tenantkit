// Package grpcmw provides gRPC unary and stream server interceptors that
// resolve the tenant for each incoming call via resolve.TenantResolver,
// confirm it exists and is active against a store.TenantStore, and
// optionally authenticate the caller via an identity.IdentityProvider --
// rejecting the call with an Unauthenticated/PermissionDenied status on
// failure and otherwise attaching the resolved tenant (and identity, if
// any) to the call context before invoking the handler. It wraps the
// gRPC server context into a resolve.Source via grpcSource; Config
// mirrors httpmw.Config.
package grpcmw

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// ErrorHandler builds the error returned to the gRPC client for a
// rejected call. code is the codes.Code grpcmw selected (Unauthenticated
// or PermissionDenied); err is the underlying error -- a
// resolver/store/IdentityProvider error, or one of grpcmw's own sentinel
// errors (errNoCredentials, errInactiveTenant, errIdentityTenantMismatch).
//
// The default wraps err.Error() directly into status.Error(code, ...),
// same as grpcmw's behavior before this hook existed -- so a backend or
// store failure's raw error text reaches the client by default, same as
// httpmw's default ErrorHandler. Override to redact it, e.g. log err
// server-side and return status.Error(code, "internal error") to the
// client instead, or attach status details via status.New(code,
// "...").WithDetails(...).Err().
type ErrorHandler func(code codes.Code, err error) error

// Config configures the interceptors returned by UnaryServerInterceptor
// and StreamServerInterceptor. Same shape and semantics as httpmw.Config
// -- see its doc comment -- with ErrorHandler as gRPC's equivalent of
// httpmw.ErrorHandler: httpmw's writes an HTTP response, gRPC has no
// response body to write, so grpcmw's builds the status error to return.
type Config struct {
	Resolvers        []resolve.TenantResolver
	TenantStore      store.TenantStore
	IdentityProvider identity.IdentityProvider
	// ErrorHandler is optional. Defaults to wrapping err.Error() into
	// status.Error(code, ...) unmodified if not set.
	ErrorHandler ErrorHandler
}

func resolveAndAuthenticate(ctx context.Context, cfg Config, errorHandler ErrorHandler) (context.Context, error) {
	src := grpcSource{ctx: ctx}

	tenantID, err := resolve.RunChain(ctx, cfg.Resolvers, src)
	if err != nil {
		return nil, errorHandler(codes.Unauthenticated, err)
	}
	if tenantID == "" {
		return nil, errorHandler(codes.Unauthenticated, errNoCredentials)
	}

	tenant, err := cfg.TenantStore.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, errorHandler(codes.PermissionDenied, err)
	}
	if !tenant.Active {
		return nil, errorHandler(codes.PermissionDenied, errInactiveTenant)
	}
	ctx = tenantkit.WithTenant(ctx, tenant)

	if cfg.IdentityProvider != nil {
		id, err := cfg.IdentityProvider.Authenticate(ctx, src)
		if err != nil {
			return nil, errorHandler(codes.Unauthenticated, err)
		}
		if id != nil {
			if id.TenantID != tenantID {
				return nil, errorHandler(codes.PermissionDenied, errIdentityTenantMismatch)
			}
			ctx = tenantkit.WithIdentity(ctx, id)
		}
	}

	return ctx, nil
}

var (
	errNoCredentials          = fmt.Errorf("grpcmw: no credentials presented")
	errInactiveTenant         = fmt.Errorf("grpcmw: tenant is inactive")
	errIdentityTenantMismatch = fmt.Errorf("grpcmw: identity's tenant does not match resolved tenant")
)

func defaultErrorHandler(code codes.Code, err error) error {
	return status.Error(code, err.Error())
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that
// resolves the tenant (and, if configured, the identity) for each unary
// call.
func UnaryServerInterceptor(cfg Config) grpc.UnaryServerInterceptor {
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx, err := resolveAndAuthenticate(ctx, cfg, errorHandler)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a grpc.StreamServerInterceptor that
// resolves the tenant (and, if configured, the identity) once at stream
// start.
func StreamServerInterceptor(cfg Config) grpc.StreamServerInterceptor {
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := resolveAndAuthenticate(ss.Context(), cfg, errorHandler)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedStream) Context() context.Context {
	return s.ctx
}
