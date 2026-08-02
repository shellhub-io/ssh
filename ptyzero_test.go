//go:build unix

package ssh

import "testing"

// Pty() reports true while emulating, and the Pty it hands back has no
// allocation behind it. Callers reasonably read Name() off that — for utmp, or
// to chown the slave — so the accessors have to survive it rather than take the
// process down.
func TestZeroPtyAccessorsDoNotPanic(t *testing.T) {
	t.Parallel()

	var p Pty
	if !p.IsZero() {
		t.Fatal("a Pty with no allocation should be zero")
	}

	if got := p.Name(); got != "" {
		t.Errorf("Name on a zero pty should be empty, got %q", got)
	}

	if _, err := p.Read(make([]byte, 1)); err == nil {
		t.Error("Read on a zero pty should fail rather than panic")
	}

	if _, err := p.Write([]byte("x")); err == nil {
		t.Error("Write on a zero pty should fail rather than panic")
	}

	if err := p.Close(); err != nil {
		t.Errorf("Close on a zero pty should be a no-op, got %v", err)
	}

	if err := p.Resize(80, 40); err == nil {
		t.Error("Resize on a zero pty should fail rather than panic")
	}
}
