package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestSessionAccessors(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			if s.PublicKey() != nil {
				t.Errorf("PublicKey() should be nil without pubkey auth, got %v", s.PublicKey())
			}
			if s.RemoteAddr() == nil {
				t.Error("RemoteAddr() should not be nil")
			}
			if s.LocalAddr() == nil {
				t.Error("LocalAddr() should not be nil")
			}
			env := s.Environ()
			if len(env) != 0 {
				t.Errorf("Environ() = %v, want empty", env)
			}
			if s.RawCommand() != "" {
				t.Errorf("RawCommand() = %q, want empty", s.RawCommand())
			}
			cmd := s.Command()
			if len(cmd) != 0 {
				t.Errorf("Command() = %v, want empty", cmd)
			}
			if s.Subsystem() != "" {
				t.Errorf("Subsystem() = %q, want empty", s.Subsystem())
			}
		},
	}, nil)
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCommand(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			if s.RawCommand() != "git-upload-pack 'test.git'" {
				t.Errorf("RawCommand() = %q", s.RawCommand())
			}
			cmd := s.Command()
			if len(cmd) != 2 || cmd[0] != "git-upload-pack" || cmd[1] != "test.git" {
				t.Errorf("Command() = %v", cmd)
			}
		},
	}, nil)
	defer cleanup()
	if err := session.Run("git-upload-pack 'test.git'"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionSubsystem(t *testing.T) {
	t.Parallel()
	srv := &Server{
		SubsystemHandlers: map[string]SubsystemHandler{
			"sftp": func(s Session) {
				if s.Subsystem() != "sftp" {
					t.Errorf("Subsystem() = %q, want %q", s.Subsystem(), "sftp")
				}
			},
		},
	}
	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()
	// Send a subsystem request manually
	ok, err := session.SendRequest("subsystem", true, gossh.Marshal(struct{ Name string }{Name: "sftp"}))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("subsystem request rejected")
	}
}

func TestSessionEnviron(t *testing.T) {
	t.Parallel()
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			env := s.Environ()
			found := false
			for _, e := range env {
				if e == "TESTVAR=hello" {
					found = true
				}
			}
			if !found {
				t.Errorf("Environ() = %v, want TESTVAR=hello", env)
			}
		},
	}, nil)
	defer cleanup()
	if err := session.Setenv("TESTVAR", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestSessionPublicKeyAccessor(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			if s.PublicKey() == nil {
				t.Error("PublicKey() should not be nil after pubkey auth")
			}
		},
	}, &gossh.ClientConfig{
		User: "testuser",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(signer),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PublicKeyAuth(func(ctx Context, key PublicKey) bool {
		return true
	}))
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}
