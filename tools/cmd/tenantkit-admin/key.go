package main

import (
	"fmt"

	"github.com/TURNERO/tenantkit/admin"
	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage API keys",
	}
	cmd.AddCommand(newKeyCreateCmd())
	cmd.AddCommand(newKeyRevokeCmd())
	cmd.AddCommand(newKeyRotateCmd())
	return cmd
}

func newKeyCreateCmd() *cobra.Command {
	var (
		tenantID string
		userID   string
		dryRun   bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would create an API key for tenant %q\n", tenantID)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			secret, err := admin.CreateAPIKey(cmd.Context(), db, tenantID, userID)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "API key (shown once, save it now):")
			fmt.Fprintln(out, "  "+secret)
			return nil
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&userID, "user", "", "user ID (omit for a tenant-level key)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newKeyRevokeCmd() *cobra.Command {
	var (
		key    string
		yes    bool
		dryRun bool
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if key == "" {
				return fmt.Errorf("--key is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintln(out, "[dry-run] would revoke the given API key")
				return nil
			}
			if !yes && !confirm(cmd, "Revoke this API key?") {
				fmt.Fprintln(out, "aborted")
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.RevokeAPIKey(cmd.Context(), db, key); err != nil {
				return err
			}
			fmt.Fprintln(out, "revoked")
			return nil
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "the plaintext API key to revoke")
	cmd.Flags().BoolVarP(&yes, "yes", "f", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newKeyRotateCmd() *cobra.Command {
	var (
		oldKey string
		dryRun bool
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate an API key (issues a new one, revokes the old one)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if oldKey == "" {
				return fmt.Errorf("--key is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintln(out, "[dry-run] would rotate the given API key")
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			newSecret, err := admin.RotateAPIKey(cmd.Context(), db, oldKey)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "new API key (shown once, save it now):")
			fmt.Fprintln(out, "  "+newSecret)
			return nil
		},
	}
	cmd.Flags().StringVar(&oldKey, "key", "", "the plaintext API key to rotate")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}
