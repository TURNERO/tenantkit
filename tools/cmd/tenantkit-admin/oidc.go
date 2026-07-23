package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TURNERO/tenantkit"
	"github.com/TURNERO/tenantkit/admin"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newOIDCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "Manage per-tenant OIDC IdP registrations",
	}
	cmd.AddCommand(newOIDCRegisterCmd())
	cmd.AddCommand(newOIDCListCmd())
	cmd.AddCommand(newOIDCShowCmd())
	cmd.AddCommand(newOIDCUpdateCmd())
	cmd.AddCommand(newOIDCRemoveCmd())
	return cmd
}

func splitCommaList(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// oidcProviderFlags holds the flags shared by "register" and "update"
// (both take the same full set of provider fields).
type oidcProviderFlags struct {
	tenantID      string
	providerID    string
	name          string
	issuerURL     string
	clientID      string
	clientSecret  string
	scopesRaw     string
	domainsRaw    string
	tenantIDClaim string
	userIDClaim   string
	usernameClaim string
	rolesClaim    string
}

// bind registers this struct's flags on fs -- shared between "register"
// and "update" since both take the identical set of provider fields.
func (f *oidcProviderFlags) bind(fs *pflag.FlagSet) {
	fs.StringVar(&f.tenantID, "tenant", "", "tenant ID")
	fs.StringVar(&f.providerID, "provider-id", "", "provider ID slug, unique within the tenant (e.g. \"okta\")")
	fs.StringVar(&f.name, "name", "", "display name for a login picker")
	fs.StringVar(&f.issuerURL, "issuer", "", "OIDC issuer URL")
	fs.StringVar(&f.clientID, "client-id", "", "OAuth2 client ID")
	fs.StringVar(&f.clientSecret, "client-secret", "", "OAuth2 client secret")
	fs.StringVar(&f.scopesRaw, "scopes", "", `comma-separated OAuth2 scopes in addition to "openid" (optional)`)
	fs.StringVar(&f.domainsRaw, "domains", "", "comma-separated email domains this provider claims (optional)")
	fs.StringVar(&f.tenantIDClaim, "tenant-id-claim", "", "ID token claim holding the tenant ID")
	fs.StringVar(&f.userIDClaim, "user-id-claim", "", `ID token claim holding the user ID (default "sub")`)
	fs.StringVar(&f.usernameClaim, "username-claim", "", `ID token claim holding the username (default "email")`)
	fs.StringVar(&f.rolesClaim, "roles-claim", "", `ID token claim holding roles (default "roles")`)
}

func (f *oidcProviderFlags) validate() error {
	if f.tenantID == "" {
		return fmt.Errorf("--tenant is required")
	}
	if f.providerID == "" {
		return fmt.Errorf("--provider-id is required")
	}
	if f.issuerURL == "" {
		return fmt.Errorf("--issuer is required")
	}
	if f.clientID == "" {
		return fmt.Errorf("--client-id is required")
	}
	if f.clientSecret == "" {
		return fmt.Errorf("--client-secret is required")
	}
	if f.tenantIDClaim == "" {
		return fmt.Errorf("--tenant-id-claim is required")
	}
	return nil
}

func (f *oidcProviderFlags) toProvider() *tenantkit.OIDCProvider {
	return &tenantkit.OIDCProvider{
		TenantID:     f.tenantID,
		ProviderID:   f.providerID,
		Name:         f.name,
		IssuerURL:    f.issuerURL,
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
		Scopes:       splitCommaList(f.scopesRaw),
		Domains:      splitCommaList(f.domainsRaw),
		ClaimsMapping: tenantkit.ClaimsMapping{
			TenantIDClaim: f.tenantIDClaim,
			UserIDClaim:   f.userIDClaim,
			UsernameClaim: f.usernameClaim,
			RolesClaim:    f.rolesClaim,
		},
	}
}

func newOIDCRegisterCmd() *cobra.Command {
	var flags oidcProviderFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new OIDC provider for a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.validate(); err != nil {
				return err
			}
			p := flags.toProvider()

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would register oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.RegisterOIDCProvider(cmd.Context(), db, p); err != nil {
				return err
			}
			fmt.Fprintf(out, "registered oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
			return nil
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newOIDCUpdateCmd() *cobra.Command {
	var flags oidcProviderFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Replace a tenant's registered OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.validate(); err != nil {
				return err
			}
			p := flags.toProvider()

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would update oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.UpdateOIDCProvider(cmd.Context(), db, p); err != nil {
				return err
			}
			fmt.Fprintf(out, "updated oidc provider %q for tenant %q\n", p.ProviderID, p.TenantID)
			return nil
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newOIDCListCmd() *cobra.Command {
	var (
		tenantID string
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a tenant's registered OIDC providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			providers, err := admin.ListOIDCProviders(cmd.Context(), db, tenantID)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(providers)
			}
			for _, p := range providers {
				fmt.Fprintf(out, "%s\t%s\t%s\n", p.ProviderID, p.Name, p.IssuerURL)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func newOIDCShowCmd() *cobra.Command {
	var (
		tenantID   string
		providerID string
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show a tenant's registered OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			if providerID == "" {
				return fmt.Errorf("--provider-id is required")
			}
			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			p, err := admin.GetOIDCProvider(cmd.Context(), db, tenantID, providerID)
			if err != nil {
				return err
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(p)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&providerID, "provider-id", "", "provider ID")
	return cmd
}

func newOIDCRemoveCmd() *cobra.Command {
	var (
		tenantID   string
		providerID string
		yes        bool
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a tenant's registered OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			if providerID == "" {
				return fmt.Errorf("--provider-id is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would remove oidc provider %q for tenant %q\n", providerID, tenantID)
				return nil
			}
			if !yes && !confirm(cmd, fmt.Sprintf("Remove oidc provider %q for tenant %q?", providerID, tenantID)) {
				fmt.Fprintln(out, "aborted")
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.RemoveOIDCProvider(cmd.Context(), db, tenantID, providerID); err != nil {
				return err
			}
			fmt.Fprintln(out, "removed")
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&providerID, "provider-id", "", "provider ID")
	cmd.Flags().BoolVarP(&yes, "yes", "f", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}
