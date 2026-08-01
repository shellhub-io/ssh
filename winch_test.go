package ssh

import (
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

type ptyReqPayload struct {
	Term                 string
	Cols, Rows, Wpx, Hpx uint32
	Modes                string
}

type winChangePayload struct {
	Cols, Rows, Wpx, Hpx uint32
}

// openSessionChannel gives the raw channel so requests can be driven one at a
// time, which is what makes the ordering inside the request loop observable.
func openSessionChannel(t *testing.T, srv *Server) gossh.Channel {
	t.Helper()

	l := newLocalListener()
	go srv.Serve(l) //nolint:errcheck
	t.Cleanup(func() { _ = srv.Close() })

	client, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go gossh.DiscardRequests(reqs)
	t.Cleanup(func() { _ = ch.Close() })

	return ch
}

// requestWithin sends a channel request that wants a reply and reports whether
// the answer arrived before the deadline.
func requestWithin(t *testing.T, ch gossh.Channel, name string, payload []byte, d time.Duration) bool {
	t.Helper()

	answered := make(chan struct{})
	go func() {
		_, _ = ch.SendRequest(name, true, payload)
		close(answered)
	}()

	select {
	case <-answered:
		return true
	case <-time.After(d):
		return false
	}
}

// winch is buffered to one and the pty request already put the initial size in
// it. The request loop sends the new size before replying, so with nothing
// draining the channel that send blocks and the loop stops answering anything
// at all — not just window-change.
//
// Nothing drains it whenever the session handler ignores the channel Pty()
// returns, which is what a server that manages its own terminal does.
func TestWindowChangeWedgesTheLoopWithNoConsumer(t *testing.T) {
	srv := &Server{
		// Never asks for the winch channel, so nothing consumes it.
		Handler: func(s Session) { <-s.Context().Done() },
	}
	ch := openSessionChannel(t, srv)

	if !requestWithin(t, ch, "pty-req", gossh.Marshal(ptyReqPayload{Term: "xterm", Cols: 80, Rows: 24}), 5*time.Second) {
		t.Fatal("pty-req went unanswered")
	}

	if !requestWithin(t, ch, "window-change", gossh.Marshal(winChangePayload{Cols: 160, Rows: 48}), 5*time.Second) {
		t.Fatal("window-change went unanswered: the request loop is wedged")
	}

	// The loop has to still be serving whatever comes next.
	if !requestWithin(t, ch, "env", gossh.Marshal(struct{ Name, Value string }{"FOO", "bar"}), 5*time.Second) {
		t.Fatal("the session stopped answering after a window-change")
	}
}

// A consumer that is briefly busy — applying the previous size is a syscall —
// leaves the one-slot buffer full, so a burst of resizes blocks the loop for as
// long as the consumer takes. It recovers, but the session stalls meanwhile,
// which is what a resize test sees as flakiness under load.
func TestWindowChangeStallsTheLoopOnASlowConsumer(t *testing.T) {
	const applying = 300 * time.Millisecond

	srv := &Server{
		Handler: func(s Session) {
			_, winch, _ := s.Pty()
			for range winch {
				time.Sleep(applying)
			}
		},
	}
	ch := openSessionChannel(t, srv)

	if !requestWithin(t, ch, "pty-req", gossh.Marshal(ptyReqPayload{Term: "xterm", Cols: 80, Rows: 24}), 5*time.Second) {
		t.Fatal("pty-req went unanswered")
	}
	// The handler only starts on shell, so ask for one before resizing.
	if !requestWithin(t, ch, "shell", nil, 5*time.Second) {
		t.Fatal("shell went unanswered")
	}

	start := time.Now()
	for i := range 8 {
		size := uint32(80 + i)
		if !requestWithin(t, ch, "window-change", gossh.Marshal(winChangePayload{Cols: size, Rows: 24}), 5*time.Second) {
			t.Fatalf("window-change %d went unanswered", i)
		}
	}
	elapsed := time.Since(start)

	// Eight resizes should not cost eight times the consumer's work: the sizes
	// in between are stale by the time they are applied.
	if elapsed > 4*applying {
		t.Errorf("a burst of 8 resizes stalled the loop for %v, dragging the session with it", elapsed)
	}
}
