package main

import (
	"encoding/json"
	"fmt"

	"github.com/TURNERO/tenantkit/admin"
	"github.com/TURNERO/tenantkit/store"
	"github.com/spf13/cobra"
)

func newTenantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Manage tenants",
	}
	cmd.AddCommand(newTenantCreateCmd())
	cmd.AddCommand(newTenantListCmd())
	cmd.AddCommand(newTenantDeactivateCmd())
	return cmd
}

func newTenantCreateCmd() *cobra.Command {
	var (
		id         string
		generateID bool
		name       string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id != "" && generateID {
				return fmt.Errorf("--id and --generate-id are mutually exclusive")
			}
			resolvedID := id
			if generateID {
				generated, err := store.GenerateTenantID()
				if err != nil {
					return fmt.Errorf("generate tenant id: %w", err)
				}
				resolvedID = generated
			}
			if resolvedID == "" {
				return fmt.Errorf("either --id or --generate-id is required")
			}

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would create tenant %q (display name %q)\n", resolvedID, name)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			t, err := admin.CreateTenant(cmd.Context(), db, resolvedID, name)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "created tenant %q (%s)\n", t.ID, t.DisplayName)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "tenant ID (mutually exclusive with --generate-id)")
	cmd.Flags().BoolVar(&generateID, "generate-id", false, "auto-generate a tenant ID")
	cmd.Flags().StringVar(&name, "name", "", "display name")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newTenantListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tenants",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			tenants, err := admin.ListTenants(cmd.Context(), db)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(tenants)
			}
			for _, t := range tenants {
				fmt.Fprintf(out, "%s\t%s\tactive=%t\n", t.ID, t.DisplayName, t.Active)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}

func newTenantDeactivateCmd() *cobra.Command {
	var (
		id     string
		yes    bool
		dryRun bool
	)
	cmd := &cobra.Command{
		Use:   "deactivate",
		Short: "Deactivate a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return fmt.Errorf("--id is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would deactivate tenant %q\n", id)
				return nil
			}
			if !yes && !confirm(cmd, fmt.Sprintf("Deactivate tenant %q?", id)) {
				fmt.Fprintln(out, "aborted")
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.DeactivateTenant(cmd.Context(), db, id); err != nil {
				return err
			}
			fmt.Fprintf(out, "deactivated tenant %q\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "tenant ID")
	cmd.Flags().BoolVarP(&yes, "yes", "f", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}
