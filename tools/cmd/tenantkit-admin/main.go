// Command tenantkit-admin provisions and manages tenantkit tenants,
// users, API keys, and client certs. It's a thin cobra-based wrapper
// around tenantkit/admin, using tenantkit/store/sqlite as its default,
// persistent backend.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/TURNERO/tenantkit/store/sqlite"
	"github.com/spf13/cobra"
)

// newRootCmd builds the full command tree from scratch. Every flag is a
// local variable captured by its command's RunE closure -- not a
// package-level var -- so each call returns a fully independent command
// tree with no state shared across calls. main calls this once; tests
// call it fresh per test case, so no test can see another test's flag
// values or leftover state.
func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenantkit-admin",
		Short: "Provision and manage tenantkit tenants, users, API keys, and client certs",
	}
	cmd.PersistentFlags().String("db", "tenantkit.db", "path to the SQLite database file (or :memory: for a throwaway one)")

	cmd.AddCommand(newTenantCmd())
	cmd.AddCommand(newKeyCmd())
	cmd.AddCommand(newUserCmd())
	cmd.AddCommand(newCertCmd())
	return cmd
}

// dbPath reads the --db persistent flag. Cobra merges persistent flags
// from ancestor commands into a leaf command's own FlagSet before RunE
// runs, so cmd.Flags() (not cmd.Root().PersistentFlags()) is the correct
// place to read it from any subcommand.
func dbPath(cmd *cobra.Command) (string, error) {
	return cmd.Flags().GetString("db")
}

func openStore(cmd *cobra.Command) (*sqlite.Store, error) {
	path, err := dbPath(cmd)
	if err != nil {
		return nil, err
	}
	db, err := sqlite.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open store at %q: %w", path, err)
	}
	return db, nil
}

// confirm prompts the operator with a yes/no question via cmd's
// configured output/input (so tests can inject both) and reports
// whether they answered yes. Only "y" or "yes" (case-insensitive) count
// as yes; anything else, including just pressing enter, is no.
func confirm(cmd *cobra.Command, prompt string) bool {
	fmt.Fprintf(cmd.OutOrStdout(), "%s [y/N]: ", prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
