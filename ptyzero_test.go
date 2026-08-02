//go:build unix

package ssh

import (
	"os/exec"
	"testing"
)

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

// Start is the accessor that matters most here, and the one the others'
// guards left out. Reached with no pty behind it, it wired the child's stdio
// to a nil file: the command started with 0, 1 and 2 closed and Start reported
// success, so the caller saw a shell that answers nothing. Asking for the
// slave's owner panicked outright.
func TestStartOnAZeroPtyFailsRatherThanLying(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		opts []PtyStartOption
	}{
		{name: "no options"},
		{name: "with job control", opts: []PtyStartOption{WithJobControl()}},
		{name: "with owner", opts: []PtyStartOption{WithOwner(0)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var p Pty

			cmd := exec.Command("/bin/echo", "started")
			if err := p.Start(cmd, tt.opts...); err == nil {
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}

				t.Fatal("Start on a zero pty reported success")
			}

			if cmd.Process != nil {
				t.Error("Start failed but left a process behind")
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
	}
}
