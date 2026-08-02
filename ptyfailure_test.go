package ssh

import (
	"errors"
	"testing"
	"time"
)

// A pty handler that fails leaves the session refusing the pty-req. What must
// not happen is the request loop getting stuck afterwards: winch is buffered to
// one and already holds the initial size, so a later window-change that still
// tries to send would block the loop forever and the session would stop
// answering anything at all.
func TestRefusedPtyDoesNotWedgeTheRequestLoop(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) { _ = s.Exit(0) },
		PtyHandler: func(Context, Session, Pty) (func() error, error) {
			return nil, errors.New("no /dev/ptmx here")
		},
	}

	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()

	if err := session.RequestPty("xterm", 40, 80, nil); err == nil {
		t.Fatal("expected the pty request to be refused")
	}

	// The loop has to still be answering. WindowChange is what would wedge it.
	done := make(chan error, 1)
	go func() {
		if err := session.WindowChange(50, 100); err != nil {
			done <- err
			return
		}
		done <- session.Run("")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session stopped answering after the pty was refused")
	}
}
