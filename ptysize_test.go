//go:build !windows

package ssh

import (
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPtyClampsAnOversizedWindowToTheTerminalMaximum(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) {
			pty, _, ok := s.Pty()
			if !ok {
				_ = s.Exit(1)

				return
			}

			cmd := exec.Command("/bin/sh", "-c", "stty size")
			if err := pty.Start(cmd); err != nil {
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

	if err := session.RequestPty("xterm", 70000, 70000, nil); err != nil {
		t.Skipf("cannot allocate a pty here: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}

	read := make(chan string, 1)

	go func() {
		out, _ := io.ReadAll(stdout)
		read <- strings.TrimSpace(string(out))
	}()

	select {
	case got := <-read:
		if got != "65535 65535" {
			t.Fatalf("stty size = %q, want %q", got, "65535 65535")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the session never closed")
	}
}
