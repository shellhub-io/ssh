package ssh

import (
	"io"
	"os/exec"
	"testing"
	"time"
)

// The library keeps the slave open for the whole session, so the master never
// reports EOF when the command exits. What has to end the session is the
// handler returning and the deferred close releasing the copies. A server that
// hands its pty to the library depends on that, so pin it.
func TestAllocatedPtySessionEndsWhenTheCommandExits(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) {
			pty, _, ok := s.Pty()
			if !ok {
				_ = s.Exit(1)

				return
			}

			cmd := exec.Command("/bin/echo", "done")
			if err := pty.Start(cmd, WithJobControl()); err != nil {
				_ = s.Exit(1)

				return
			}

			_ = cmd.Wait()
		},
	}
	if err := AllocatePty()(srv); err != nil {
		t.Fatal(err)
	}

	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()

	if err := session.RequestPty("xterm", 40, 80, nil); err != nil {
		t.Skipf("cannot allocate a pty here: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}

	// Reading to EOF is the client-visible end of the session.
	read := make(chan []byte, 1)
	go func() {
		out, _ := io.ReadAll(stdout)
		read <- out
	}()

	select {
	case out := <-read:
		t.Logf("session closed, client saw %q", out)
	case <-time.After(10 * time.Second):
		t.Fatal("the session never closed after the command exited")
	}
}
