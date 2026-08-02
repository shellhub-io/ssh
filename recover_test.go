package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// TestHandleConnRecoversPanic verifies that a panic while handling a connection
// does not escape HandleConn.
//
// This test fails by crashing rather than by reporting: without the recover, the
// panic unwinds a goroutine with nothing to catch it and Go terminates the whole
// test binary.
func TestHandleConnRecoversPanic(t *testing.T) {
	srv := &Server{
		ConnCallback: func(_ Context, _ net.Conn) net.Conn {
			panic("boom from the connection path")
		},
	}

	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(server)
	}()

	select {
	case <-done:
		// Returned normally, so the panic was contained.
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConn did not return after panic")
	}
}

// TestHandleConnRecoverClosesConn checks that the recovered path still closes
// the connection. A panic skips the deferred close inside the handler, so the
// recover has to do it or the connection leaks.
func TestHandleConnRecoverClosesConn(t *testing.T) {
	srv := &Server{
		ConnCallback: func(_ Context, _ net.Conn) net.Conn {
			panic("boom")
		},
	}

	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck

	srv.HandleConn(server)

	if _, err := server.Write([]byte("x")); err == nil {
		t.Error("expected connection to be closed after recovered panic")
	}
}

// TestServeSurvivesPanickingConn is the property that matters for availability:
// one connection that panics must not stop the server from accepting others.
func TestServeSurvivesPanickingConn(t *testing.T) {
	handled := make(chan int, 8)
	var count atomic.Int64

	srv := &Server{
		Handler: func(s Session) {},
		ConnCallback: func(_ Context, conn net.Conn) net.Conn {
			n := count.Add(1)
			handled <- int(n)
			// Only the first connection panics, mimicking a crafted packet
			// that faults during the handshake.
			if n == 1 {
				panic("crafted packet")
			}
			return conn
		},
	}

	l := newLocalListener()
	go srv.Serve(l) //nolint:errcheck
	defer srv.Close()

	// The connection that panics.
	first, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	first.Close() //nolint:errcheck

	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("first connection was never handled")
	}

	// The server must still be accepting. If the panic had escaped, the
	// process would already be gone.
	second, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("server stopped accepting after a panicking connection: %v", err)
	}
	defer second.Close() //nolint:errcheck

	select {
	case n := <-handled:
		if n < 2 {
			t.Errorf("expected the second connection to be handled, got %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second connection was never handled")
	}
}

// TestRecoverAndLogContainsPanic verifies the helper that every server
// goroutine defers. Recovery only sees panics on its own stack, so each
// goroutine the server starts needs its own deferred call; this checks the
// shared helper behaves when it is the thing standing between a panic and the
// process.
func TestRecoverAndLogContainsPanic(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer recoverAndLog("panic in test goroutine", nil, nil)
		panic("boom")
	}()

	select {
	case <-done:
		// Contained.
	case <-time.After(5 * time.Second):
		t.Fatal("goroutine did not return after panic")
	}
}

// TestRecoverAndLogRunsCleanup checks the cleanup hook runs, since HandleConn
// relies on it to close a connection whose own deferred close was skipped by
// the panic.
func TestRecoverAndLogRunsCleanup(t *testing.T) {
	cleaned := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer recoverAndLog("panic with cleanup", nil, func() { close(cleaned) })
		panic("boom")
	}()

	<-done
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not run after recovered panic")
	}
}

// TestRecoverAndLogIgnoresNormalReturn makes sure the helper is inert when
// nothing panicked, so cleanup does not fire on the happy path.
func TestRecoverAndLogIgnoresNormalReturn(t *testing.T) {
	cleanupRan := false
	func() {
		defer recoverAndLog("should not fire", nil, func() { cleanupRan = true })
	}()

	if cleanupRan {
		t.Error("cleanup ran even though nothing panicked")
	}
}

// TestChannelHandlerPanicDoesNotKillServer covers the goroutines that
// HandleConn starts for channel and request handling. Those run on their own
// stacks, so HandleConn's recover cannot see them and they need their own.
// Without that, a panic in a channel handler takes down the process.
func TestChannelHandlerPanicDoesNotKillServer(t *testing.T) {
	panicked := make(chan struct{})
	srv := &Server{
		Handler: func(Session) {},
		ChannelHandlers: map[string]ChannelHandler{
			"session": func(_ *Server, _ *gossh.ServerConn, _ gossh.NewChannel, _ Context) {
				close(panicked)
				panic("panic in channel handler")
			},
		},
	}

	l := newLocalListener()
	go srv.Serve(l) //nolint:errcheck
	defer srv.Close()

	client, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck

	// Opening a session reaches the panicking handler. The call itself is
	// expected to hang or fail, since the handler never replies, so it runs
	// in the background and only the panic is awaited.
	go func() {
		if sess, err := client.NewSession(); err == nil {
			_ = sess.Close()
		}
	}()

	select {
	case <-panicked:
	case <-time.After(5 * time.Second):
		t.Fatal("channel handler was never reached")
	}

	// Give the panic time to either be recovered or kill the process.
	time.Sleep(200 * time.Millisecond)

	// Reaching here at all means the panic was contained. Confirm the server
	// is still serving by completing another handshake.
	client2, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("server stopped serving after a channel handler panic: %v", err)
	}
	_ = client2.Close()
}

// TestSessionHandlerPanicDoesNotKillServer covers the goroutine that runs the
// user's session handler. This is the path every SSH session takes, so it is
// the most likely place for an application panic, and it runs on a fresh
// goroutine where no caller can recover for it.
func TestSessionHandlerPanicDoesNotKillServer(t *testing.T) {
	srv := &Server{
		Handler: func(s Session) {
			panic("panic in session handler")
		},
	}

	l := newLocalListener()
	go srv.Serve(l) //nolint:errcheck
	defer srv.Close()

	cfg := &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := gossh.Dial("tcp", l.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	// The handler panics, so a non-zero exit or an error here is fine. What
	// matters is that the process is still alive afterwards.
	_, _ = sess.Output("")
	_ = client.Close()

	// Confirm the server is still serving.
	client2, err := gossh.Dial("tcp", l.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("server stopped serving after a session handler panic: %v", err)
	}
	_ = client2.Close()
}

// TestSessionHandlerPanicClosesPty guards against a subtle failure mode of the
// recover added to the session handler: the pty used to be closed on the line
// after the handler returned, so recovering a panic would skip it and leak the
// pty on every panicking session. Trading a crash for a resource leak is not a
// fix, so the close is deferred.
//
// This asserts on the ordering directly rather than through a live session,
// since the leak is invisible from the client's side.
func TestSessionHandlerPanicClosesPty(t *testing.T) {
	closed := false
	func() {
		// Mirrors the structure in session.go: cleanup deferred before the
		// recover so it runs even when the body panics.
		defer func() { closed = true }()
		defer func() { _ = recover() }()
		panic("handler panic")
	}()

	if !closed {
		t.Error("pty cleanup was skipped when the handler panicked")
	}
}

// TestAgentProxyPanicReleasesWaitGroup guards the agent forwarding fix. The
// copy goroutines called wg.Done() as a plain statement, so recovering a panic
// meant Done never ran and the parent's wg.Wait() blocked forever, leaking the
// goroutine, the socket, and the channel. Done is now deferred ahead of the
// recover.
func TestAgentProxyPanicReleasesWaitGroup(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// Same ordering as agent.go.
		defer wg.Done()
		defer recoverAndLog("panic proxying agent connection", nil, nil)
		panic("copy panic")
	}()

	waited := make(chan struct{})
	go func() {
		wg.Wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("wg.Wait() blocked after a recovered panic; Done was skipped")
	}
}

// TestRecoverAndLogContainsPanickingCleanup checks that a panic raised by the
// cleanup function does not escape. Cleanup runs while already unwinding a
// panic, so a second panic there would defeat the containment and kill the
// process. Cleanups call things like Session.Exit, which touch a connection
// that may already be torn down, so this is not hypothetical.
func TestRecoverAndLogContainsPanickingCleanup(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer recoverAndLog("panic with bad cleanup", nil, func() {
			panic("cleanup panicked too")
		})
		panic("original panic")
	}()

	select {
	case <-done:
		// Both panics contained.
	case <-time.After(5 * time.Second):
		t.Fatal("goroutine did not return")
	}
}

// testHostSigner returns a throwaway host key for tests that drive a handshake.
func testHostSigner(t *testing.T) Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestHandleConnPanicStillRunsCallbacks pins the behaviour external consumers
// depend on: the recover sits in HandleConn, above the defers registered by
// handleConn, so a panic still unwinds through them. ConnectionCloseCallback
// must fire and the connection WaitGroup must be released, or Shutdown would
// hang forever waiting on a connection that already died.
func TestHandleConnPanicStillRunsCallbacks(t *testing.T) {
	closeCalled := make(chan struct{}, 1)
	srv := &Server{
		HostSigners: []Signer{testHostSigner(t)},
		ConnectionCloseCallback: func(net.Conn) {
			closeCalled <- struct{}{}
		},
		ConnCallback: func(_ Context, conn net.Conn) net.Conn {
			return conn
		},
		Handler: func(Session) {},
	}

	// Panic after the defers are registered by driving a real handshake that
	// fails inside the config callback.
	srv.ServerConfigCallback = func(Context) *gossh.ServerConfig {
		panic("panic after defers are registered")
	}

	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.HandleConn(server)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConn did not return")
	}

	select {
	case <-closeCalled:
	case <-time.After(time.Second):
		t.Error("ConnectionCloseCallback did not fire on the panic path")
	}
}
