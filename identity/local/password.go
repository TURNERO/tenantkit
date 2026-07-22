package local

import (
	"context"
	"errors"
	"fmt"

	"github.com/TURNERO/tenantkit/store"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash is a fixed bcrypt hash with no known matching password, used
// to burn comparable time on LoginWithPassword's unknown-user/no-password
// paths so its timing doesn't leak whether a username exists -- a real
// bcrypt.CompareHashAndPassword call is measurably slower than an early
// return, and that gap is measurable over enough attempts.
const dummyHash = "$2a$10$CwTycUXWue0Thq9StjUM0uJ8Bm4/RGyGbYAgQtdRlz/DL6P/n2DDW"

// SetPassword hashes password and stores it for (tenantID, userID). It
// does not create the user -- tenantID/userID must already exist in the
// UserStore Local was constructed with (e.g. via
// tenantkit/admin.CreateUser); a nonexistent user is not checked here
// and simply orphans a credential record no user can ever log in with.
func (l *Local) SetPassword(ctx context.Context, tenantID, userID, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("tenantkit/identity/local: hash password: %w", err)
	}
	if err := l.creds.SetPasswordHash(ctx, tenantID, userID, string(hash)); err != nil {
		return fmt.Errorf("tenantkit/identity/local: set password: %w", err)
	}
	return nil
}

// LoginWithPassword validates username/password within tenantID and, on
// success, issues a session token. It returns ErrInvalidCredentials for
// an unknown username, a user with no password set, and a wrong
// password alike -- a caller can never distinguish these from the error
// alone.
func (l *Local) LoginWithPassword(ctx context.Context, tenantID, username, password string) (string, error) {
	ident, err := l.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("tenantkit/identity/local: look up user: %w", err)
	}

	hash, err := l.creds.GetPasswordHash(ctx, tenantID, ident.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("tenantkit/identity/local: get password hash: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	token, err := l.sessions.CreateSession(ctx, tenantID, ident.UserID, l.cfg.SessionTTL)
	if err != nil {
		return "", fmt.Errorf("tenantkit/identity/local: create session: %w", err)
	}
	return token, nil
}

// Logout deletes the session identified by token. Deleting an
// already-expired or unknown token is not an error -- the end state (no
// valid session for that token) is the same either way.
func (l *Local) Logout(ctx context.Context, token string) error {
	if err := l.sessions.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("tenantkit/identity/local: logout: %w", err)
	}
	return nil
}
