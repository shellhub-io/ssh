//go:build unix

package ssh

import (
	"os"
	"os/exec"
	"testing"
)

// The slave is created owned by whoever runs the server. A server that drops
// the command to another user needs the slave to follow, or the command cannot
// write to its own terminal.
func TestWithOwnerChownsTheSlave(t *testing.T) {
	t.Parallel()

	p, err := newPty(nil, "xterm", Window{Width: 80, Height: 40}, nil)
	if err != nil {
		t.Skipf("cannot allocate a pty here: %v", err)
	}
	defer p.Close() //nolint:errcheck

	before, err := os.Stat(p.Slave.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Chowning to our own uid is a no-op the kernel allows unprivileged, so it
	// exercises the call without needing root.
	uid := os.Getuid()
	cmd := exec.Command("true")
	if err := p.start(cmd, ptyStartConfig{owner: &uid}); err != nil {
		t.Fatalf("start with WithOwner: %v", err)
	}
	defer cmd.Wait() //nolint:errcheck

	after, err := os.Stat(p.Slave.Name())
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Errorf("chown should not touch the mode: %v became %v", before.Mode(), after.Mode())
	}
}

func TestWithOwnerReportsAFailedChown(t *testing.T) {
	t.Parallel()

	if os.Getuid() == 0 {
		t.Skip("running as root, chown to another uid would succeed")
	}

	p, err := newPty(nil, "xterm", Window{Width: 80, Height: 40}, nil)
	if err != nil {
		t.Skipf("cannot allocate a pty here: %v", err)
	}
	defer p.Close() //nolint:errcheck

	// An unprivileged process cannot give a file away.
	other := 1
	if err := p.start(exec.Command("true"), ptyStartConfig{owner: &other}); err == nil {
		t.Fatal("expected the chown failure to surface instead of starting the command")
	}
}
