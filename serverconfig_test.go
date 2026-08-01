package ssh

import (
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// A ServerConfigCallback that installs an auth callback must win over the
// handler overlay, otherwise the callback it set is silently discarded and the
// server authenticates through a path the caller did not configure.
func TestServerConfigCallbackKeepsItsAuthCallbacks(t *testing.T) {
	t.Parallel()

	fromConfig := func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
		return nil, nil
	}

	srv := &Server{
		PublicKeyHandler: func(Context, PublicKey) bool { return true },
		PasswordHandler:  func(Context, string) bool { return true },
		ServerConfigCallback: func(Context) *gossh.ServerConfig {
			return &gossh.ServerConfig{PublicKeyCallback: fromConfig}
		},
	}

	ctx, cancel := newContext(srv)
	defer cancel()

	config := srv.config(ctx)

	if config.PublicKeyCallback == nil {
		t.Fatal("expected the callback from ServerConfigCallback to survive")
	}
	// Comparing behaviour rather than function identity: the overlay reports
	// permission denied for a handler that returns true only if it replaced us.
	if _, err := config.PublicKeyCallback(nil, nil); err != nil {
		t.Fatalf("expected the config's own callback to run, got %v", err)
	}

	// The handler overlay still applies where the config left a gap.
	if config.PasswordCallback == nil {
		t.Fatal("expected PasswordHandler to fill the unset PasswordCallback")
	}
}
