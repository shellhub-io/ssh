package ssh

import (
	"errors"
	"sync/atomic"
	"testing"
)

// A server that allocates a pty needs to see the allocation fail: the request
// loop refuses the pty-req and carries on, so wrapping the handler is the only
// place left to log why, or to refuse the session outright.
func TestAllocatePtyHandlerCanBeWrapped(t *testing.T) {
	t.Parallel()

	var (
		called atomic.Bool
		failed atomic.Bool
	)

	srv := &Server{
		Handler: func(s Session) { _ = s.Exit(0) },
		PtyHandler: func(ctx Context, s Session, pty Pty) (func() error, error) {
			called.Store(true)
			closer, err := AllocatePtyHandler(ctx, s, pty)
			if err != nil {
				failed.Store(true)
			}
			return closer, err
		},
	}

	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()

	if err := session.RequestPty("xterm", 40, 80, nil); err != nil {
		t.Skipf("cannot allocate a pty here: %v", err)
	}

	if !called.Load() {
		t.Fatal("the wrapper should have run")
	}
	if failed.Load() {
		t.Fatal("allocation was expected to succeed here")
	}
}

func TestWrappingSeesTheAllocationError(t *testing.T) {
	t.Parallel()

	var seen atomic.Value

	srv := &Server{
		Handler: func(s Session) { _ = s.Exit(0) },
		PtyHandler: func(Context, Session, Pty) (func() error, error) {
			err := errors.New("no /dev/ptmx here")
			seen.Store(err.Error())
			return nil, err
		},
	}

	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()

	if err := session.RequestPty("xterm", 40, 80, nil); err == nil {
		t.Fatal("expected the pty request to be refused")
	}
	if got, _ := seen.Load().(string); got != "no /dev/ptmx here" {
		t.Fatalf("the server never saw the failure, got %q", got)
	}
}
