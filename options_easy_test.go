package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestPublicKeyAuthOption(t *testing.T) {
	t.Parallel()
	called := false
	srv := &Server{}
	if err := srv.SetOption(PublicKeyAuth(func(ctx Context, key PublicKey) bool {
		called = true
		return true
	})); err != nil {
		t.Fatal(err)
	}
	if srv.PublicKeyHandler == nil {
		t.Fatal("PublicKeyHandler not set")
	}
	ctx, cancel := newContext(srv)
	defer cancel()
	srv.PublicKeyHandler(ctx, nil)
	if !called {
		t.Fatal("handler not called")
	}
}

func TestHostKeyFileOption(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := &Server{}
	if err := srv.SetOption(HostKeyFile(path)); err != nil {
		t.Fatal(err)
	}
	if len(srv.HostSigners) != 1 {
		t.Fatalf("expected 1 host signer, got %d", len(srv.HostSigners))
	}
}

func TestHostKeyFileOptionMissing(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	if err := srv.SetOption(HostKeyFile("/nonexistent")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHostKeyPEMOption(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{}
	if err := srv.SetOption(HostKeyPEM(pem.EncodeToMemory(block))); err != nil {
		t.Fatal(err)
	}
	if len(srv.HostSigners) != 1 {
		t.Fatalf("expected 1 host signer, got %d", len(srv.HostSigners))
	}
}

func TestHostKeyPEMOptionInvalid(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	if err := srv.SetOption(HostKeyPEM([]byte("not a key"))); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestKeyboardInteractiveAuthOption(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	if err := srv.SetOption(KeyboardInteractiveAuth(func(ctx Context, challenge gossh.KeyboardInteractiveChallenge) bool {
		return true
	})); err != nil {
		t.Fatal(err)
	}
	if srv.KeyboardInteractiveHandler == nil {
		t.Fatal("KeyboardInteractiveHandler not set")
	}
}

func TestNoPtyOption(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	if err := srv.SetOption(NoPty()); err != nil {
		t.Fatal(err)
	}
	if srv.PtyCallback == nil {
		t.Fatal("PtyCallback not set")
	}
	ctx, cancel := newContext(srv)
	defer cancel()
	if srv.PtyCallback(ctx, Pty{}) {
		t.Fatal("NoPty should deny PTY requests")
	}
}

func TestEmulatePtyOption(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	if err := srv.SetOption(EmulatePty()); err != nil {
		t.Fatal(err)
	}
	if srv.PtyHandler == nil {
		t.Fatal("PtyHandler not set")
	}
	ctx, cancel := newContext(srv)
	defer cancel()
	closer, err := srv.PtyHandler(ctx, nil, Pty{})
	if err != nil {
		t.Fatal(err)
	}
	if closer == nil {
		t.Fatal("expected closer")
	}
	if err := closer(); err != nil {
		t.Fatal(err)
	}
	if ctx.Value(contextKeyEmulatePty) != true {
		t.Fatal("emulate-pty context key not set")
	}
}

func TestAllocatePtyOption(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	if err := srv.SetOption(AllocatePty()); err != nil {
		t.Fatal(err)
	}
	if srv.PtyHandler == nil {
		t.Fatal("PtyHandler not set")
	}
}
