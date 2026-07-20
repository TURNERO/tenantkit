# tenantkit

A store-agnostic multi-tenancy library for Go services.

Most multi-tenant services end up solving the same handful of problems from
scratch: figure out which tenant a request belongs to, authenticate whoever
is making it, look up tenant/user/API-key records, and make all of that
available to request handlers. tenantkit packages that recurring shape as a
library instead of a framework, so you don't re-derive it for every new
service.

## What it does

- **Tenant resolution** — a pluggable `TenantResolver` chain figures out
  which tenant a request belongs to (API key, session, header, subdomain,
  or a strategy you write yourself), for both HTTP and gRPC.
- **User + API key management** — interfaces for storing and looking up
  tenants, users, and API keys (both tenant-level service keys and
  user-level keys), so identity data can live in whatever database you
  already use.
- **Pluggable identity** — the same `IdentityProvider` interface is
  satisfied by a built-in local implementation (WebAuthn/bcrypt + sessions)
  and by an OIDC adapter, so you can swap in an external identity provider
  (Auth0, Okta, Clerk, Keycloak, Zitadel, or anything else that speaks
  OIDC) without changing anything downstream.
- **Middleware, not a framework** — `net/http` middleware and gRPC
  interceptors populate request context with the resolved tenant and
  identity; everything else about your service stays exactly as it was.

## What it deliberately doesn't do

- **No database access.** tenantkit defines storage interfaces
  (`TenantStore`, `UserStore`, `APIKeyStore`); it never talks to a database
  itself. You implement those interfaces against whatever you're already
  using — SQL, NoSQL, or otherwise.
- **No store-specific data isolation.** Row-level security, tenant-scoped
  query filters, and similar enforcement live in your own data layer, since
  they're inherently specific to whatever store you're using.
- **No authorization/RBAC engine.** Identities carry a list of role
  strings; interpreting them is up to you. Pair tenantkit with a policy
  engine if you need one.
- **No opinionated admin HTTP API.** Tenant/user/key provisioning is a
  CLI (`cmd/tenantkit-admin`), production-usable on its own (subcommands,
  confirmation prompts, `--dry-run`, `--json` output) and backed by an
  importable operations package (`tenantkit/admin`) for consumers who
  need to compose provisioning with their own extra steps.

## Status

Early design stage — see `docs/superpowers/specs/` for the current design
document. Not yet ready for production use.

## License

MIT — see [LICENSE](LICENSE).
