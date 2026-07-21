package grpcmw

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/identity"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/TURNERO/tenantkit/store"
)

// Config configures the interceptors returned by UnaryServerInterceptor
// and StreamServerInterceptor. Same shape and semantics as httpmw.Config
// -- see its doc comment -- minus an HTTP-specific ErrorHandler; gRPC
// rejections are reported via status codes instead.
type Config struct {
	Resolvers        []resolve.TenantResolver
	TenantStore      store.TenantStore
	IdentityProvider identity.IdentityProvider
}

func resolveAndAuthenticate(ctx context.Context, cfg Config) (context.Context, error) {
	src := grpcSource{ctx: ctx}

	tenantID, err := resolve.RunChain(ctx, cfg.Resolvers, src)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if tenantID == "" {
		return nil, status.Error(codes.Unauthenticated, "grpcmw: no credentials presented")
	}

	tenant, err := cfg.TenantStore.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if !tenant.Active {
		return nil, status.Error(codes.PermissionDenied, "grpcmw: tenant is inactive")
	}
	ctx = tenantkit.WithTenant(ctx, tenant)

	if cfg.IdentityProvider != nil {
		id, err := cfg.IdentityProvider.Authenticate(ctx, src)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if id != nil {
			if id.TenantID != tenantID {
				return nil, status.Error(codes.PermissionDenied, "grpcmw: identity's tenant does not match resolved tenant")
			}
			ctx = tenantkit.WithIdentity(ctx, id)
		}
	}

	return ctx, nil
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that
// resolves the tenant (and, if configured, the identity) for each unary
// call.
func UnaryServerInterceptor(cfg Config) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx, err := resolveAndAuthenticate(ctx, cfg)
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
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := resolveAndAuthenticate(ss.Context(), cfg)
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
