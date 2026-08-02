package ssh

import (
	"fmt"
	"io"
	"os/exec"
	"testing"
	"time"
)

// A command that writes a burst and exits at once used to lose the end of it.
// Nothing ordered the copy out of the pty against the close of the channel, so
// Exit closed the channel under the copy and whatever the pty still held was
// written into it and dropped. The loss was silent: the copy's error was
// discarded, and it only showed up as output the user never saw.
//
// Run this with -count high enough to lose the race: it reproduced at roughly
// one run in fifty under -race, and not at all in a single pass.
func TestPtyOutputSurvivesTheCommandExiting(t *testing.T) {
	t.Parallel()

	const size = 200000

	srv := &Server{
		Handler: func(s Session) {
			pty, _, ok := s.Pty()
			if !ok {
				_ = s.Exit(1)

				return
			}

			// No newlines: the terminal would turn each one into two bytes and
			// the count would say nothing about what was lost.
			cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("head -c %d /dev/zero | tr '\\0' x", size))
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

	read := make(chan int, 1)

	go func() {
		out, _ := io.ReadAll(stdout)
		read <- len(out)
	}()

	select {
	case got := <-read:
		if got != size {
			t.Fatalf("client saw %d of %d bytes, lost %d", got, size, size-got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the session never closed")
	}
}

// The drain waits for the pty to run dry, and a process the command leaves
// behind holds the terminal open with nothing more to read. The wait has to
// give up on its own, or one backgrounded process would strand the session.
func TestPtyDrainGivesUpOnALingeringProcess(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) {
			pty, _, ok := s.Pty()
			if !ok {
				_ = s.Exit(1)

				return
			}

			// The backgrounded sleep inherits the terminal and outlives the
			// shell that started it.
			cmd := exec.Command("/bin/sh", "-c", "sleep 300 & echo done")
			if err := pty.Start(cmd, WithJobControl()); err != nil {
				_ = s.Exit(1)

				return
			}

			_ = cmd.Wait()

			if cmd.Process != nil {
				t.Cleanup(func() { _ = cmd.Process.Kill() })
			}
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

	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = session.Wait()
	}()

	select {
	case <-done:
	case <-time.After(ptyDrainTimeout + 15*time.Second):
		t.Fatal("the session outlived the drain timeout")
	}
}
