package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/TURNERO/tenantkit/admin"
	"github.com/TURNERO/tenantkit/resolve"
	"github.com/spf13/cobra"
)

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage mTLS client certificates",
	}
	cmd.AddCommand(newCertRegisterCmd())
	cmd.AddCommand(newCertRevokeCmd())
	return cmd
}

// readCertFile reads a certificate file, accepting either PEM
// ("-----BEGIN CERTIFICATE-----") or raw DER encoding.
func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func newCertRegisterCmd() *cobra.Command {
	var (
		certFile string
		tenantID string
		userID   string
		dryRun   bool
	)
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a client certificate for mTLS",
		RunE: func(cmd *cobra.Command, args []string) error {
			if certFile == "" {
				return fmt.Errorf("--cert-file is required")
			}
			if tenantID == "" {
				return fmt.Errorf("--tenant is required")
			}

			cert, err := readCertFile(certFile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would register cert %s for tenant %q\n", resolve.CertFingerprint(cert), tenantID)
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			c, err := admin.RegisterClientCert(cmd.Context(), db, cert, tenantID, userID)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "registered cert for tenant %q, fingerprint:\n", c.TenantID)
			fmt.Fprintln(out, "  "+c.Fingerprint)
			return nil
		},
	}
	cmd.Flags().StringVar(&certFile, "cert-file", "", "path to the certificate file (PEM or DER)")
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID")
	cmd.Flags().StringVar(&userID, "user", "", "user ID (omit for a tenant-level cert)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}

func newCertRevokeCmd() *cobra.Command {
	var (
		fingerprint string
		yes         bool
		dryRun      bool
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a client certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if fingerprint == "" {
				return fmt.Errorf("--fingerprint is required")
			}
			out := cmd.OutOrStdout()
			if dryRun {
				fmt.Fprintf(out, "[dry-run] would revoke cert %s\n", fingerprint)
				return nil
			}
			if !yes && !confirm(cmd, fmt.Sprintf("Revoke cert %s?", fingerprint)) {
				fmt.Fprintln(out, "aborted")
				return nil
			}

			db, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := admin.RevokeClientCert(cmd.Context(), db, fingerprint); err != nil {
				return err
			}
			fmt.Fprintln(out, "revoked")
			return nil
		},
	}
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "the fingerprint printed at registration time")
	cmd.Flags().BoolVarP(&yes, "yes", "f", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print what would happen without making the change")
	return cmd
}
