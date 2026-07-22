package main

import (
	"fmt"
	"strings"

	"github.com/TURNERO/tenantkit/admin"
	"github.com/TURNERO/tenantkit/store"
	"github.com/spf13/cobra"
)

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
	}
	cmd.AddCommand(newUserCreateCmd())
	return cmd
}

func newUserCreateCmd() *cobra.Command {
	var (
		userID     string
		generateID bool
		tenantID   string
		username   string
		rolesRaw   string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if userID != "" && generateID {
				return fmt.Errorf("--user-id and --generate-user-id are mutually exclusive")
			}
			resolvedID := userID
			if generateID {
				generated, err := store.GenerateSecret()
				if err != nil {
					return fmt.Errorf("generate user id: %w", err)
				}
				resolvedID = generated
			}
			if resolvedID == "" {
				return fmt.Errorf("either --user-id or --generate-user-id is required")
			}
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			if username == "" {
				return fmt.Errorf("--username is required")
			}

			var roles []string
			if rolesRaw != "" {
				roles = strings.Split(rolesRaw, ",")
			}

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would create user %q (tenant %q, username %q, roles %v)\n", resolvedID, tenantID, username, roles)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			u, err := admin.CreateUser(cmd.Context(), db, resolvedID, tenantID, username, roles)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "created user %q (tenant %q, username %q)\n", u.UserID, u.TenantID, u.Username)
			return nil
		},
	}
	cmd.Flags().StringVar(&userID, "user-id", "", "user ID (mutually exclusive with --generate-user-id)")
	cmd.Flags().BoolVar(&generateID, "generate-user-id", false, "auto-generate a user ID")
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&username, "username", "", "username")
	cmd.Flags().StringVar(&rolesRaw, "roles", "", "comma-separated roles (optional)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}
