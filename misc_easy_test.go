package ssh

import (
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestContextAddrs(t *testing.T) {
	t.Parallel()
	ctx, cancel := newContext(nil)
	defer cancel()

	if ctx.RemoteAddr() != nil {
		t.Error("RemoteAddr() should be nil before metadata")
	}
	if ctx.LocalAddr() != nil {
		t.Error("LocalAddr() should be nil before metadata")
	}

	conn := mockConnMetadata{user: "test", sessionID: []byte("id")}
	applyConnMetadata(ctx, conn)

	// mockConnMetadata returns nil for both addrs
	if ctx.RemoteAddr() != nil {
		t.Error("RemoteAddr() should be nil with mock")
	}
	if ctx.LocalAddr() != nil {
		t.Error("LocalAddr() should be nil with mock")
	}
}

func TestServerHandle(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	srv.Handle(func(s Session) {})
	if srv.Handler == nil {
		t.Fatal("Handler not set")
	}
}

func TestListenAndServe(t *testing.T) {
	t.Parallel()
	srv := &Server{Addr: "127.0.0.1:0"}
	l := newLocalListener()
	srv.Addr = l.Addr().String()
	l.Close()
	srv.Handler = func(s Session) {}

	done := make(chan error, 1)
	go func() {
		done <- srv.ListenAndServe()
	}()

	// Connect to trigger the server
	cfg := &gossh.ClientConfig{
		User:            "test",
		Auth:            []gossh.AuthMethod{gossh.Password("test")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	// Wait for the server to start
	var client *gossh.Client
	var err error
	for i := 0; i < 10; i++ {
		client, err = gossh.Dial("tcp", srv.Addr, cfg)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	client.Close()

	srv.Close()
	<-done
}

func TestListenAndServeBadAddr(t *testing.T) {
	t.Parallel()
	srv := &Server{Addr: "invalid://addr"}
	err := srv.ListenAndServe()
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}
