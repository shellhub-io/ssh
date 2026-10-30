package ssh

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

var sampleServerResponse = []byte("Hello world")

func sampleSocketServer() net.Listener {
	l := newLocalListener()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Write(sampleServerResponse)
		conn.Close()
	}()

	return l
}

func newTestSessionWithForwarding(t *testing.T, forwardingEnabled bool) (net.Listener, *gossh.Client, func()) {
	l := sampleSocketServer()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalPortForwardingCallback: func(ctx Context, destinationHost string, destinationPort uint32) bool {
			addr := net.JoinHostPort(destinationHost, strconv.FormatInt(int64(destinationPort), 10))
			if addr != l.Addr().String() {
				panic("unexpected destinationHost: " + addr)
			}
			return forwardingEnabled
		},
	}, nil)

	return l, client, func() {
		cleanup()
		l.Close()
	}
}

func TestLocalPortForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}
}

func TestLocalPortForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "port forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func newTestSessionForwardingTo(t *testing.T, serve func(net.Conn)) (string, *gossh.Client, func()) {
	l := newLocalListener()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalPortForwardingCallback: func(ctx Context, destinationHost string, destinationPort uint32) bool {
			return true
		},
	}, nil)

	return l.Addr().String(), client, func() {
		cleanup()
		l.Close()
	}
}

func closeWrite(t *testing.T, conn net.Conn) {
	t.Helper()

	writeCloser, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T cannot half-close", conn)
	}
	if err := writeCloser.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func readAllWithin(t *testing.T, r io.Reader) []byte {
	t.Helper()

	received := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		received <- data
	}()

	select {
	case data := <-received:
		return data
	case <-time.After(5 * time.Second):
		t.Fatal("never read to EOF")
		return nil
	}
}

func TestLocalPortForwardingDeliversTheReplyAfterTheClientHalfCloses(t *testing.T) {
	t.Parallel()

	addr, client, cleanup := newTestSessionForwardingTo(t, func(conn net.Conn) {
		request, _ := io.ReadAll(conn)
		conn.Write(append([]byte("reply to "), request...))
	})
	defer cleanup()

	conn, err := client.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	closeWrite(t, conn)

	if result := readAllWithin(t, conn); string(result) != "reply to request" {
		t.Fatalf("result = %q; want %q", result, "reply to request")
	}
}

func TestLocalPortForwardingDeliversTheUploadAfterTheDeviceHalfCloses(t *testing.T) {
	t.Parallel()

	uploaded := make(chan []byte, 1)
	addr, client, cleanup := newTestSessionForwardingTo(t, func(conn net.Conn) {
		conn.Write([]byte("banner"))
		conn.(*net.TCPConn).CloseWrite()
		data, _ := io.ReadAll(conn)
		uploaded <- data
	})
	defer cleanup()

	conn, err := client.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	if banner := readAllWithin(t, conn); string(banner) != "banner" {
		t.Fatalf("banner = %q; want %q", banner, "banner")
	}

	if _, err := conn.Write([]byte("upload")); err != nil {
		t.Fatal(err)
	}
	closeWrite(t, conn)

	select {
	case data := <-uploaded:
		if string(data) != "upload" {
			t.Fatalf("uploaded = %q; want %q", data, "upload")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the device never read the upload to EOF")
	}
}

func forwardHandlerRunning() bool {
	stacks := make([]byte, 1<<20)
	n := runtime.Stack(stacks, true)
	return bytes.Contains(stacks[:n], []byte("ssh.DirectTCPIPHandler"))
}

func TestLocalPortForwardingReleasesAnIdleTargetWhenTheClientCloses(t *testing.T) {
	released := make(chan struct{})
	t.Cleanup(func() { close(released) })

	addr, client, cleanup := newTestSessionForwardingTo(t, func(conn net.Conn) {
		<-released
	})
	defer cleanup()

	conn, err := client.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for forwardHandlerRunning() {
		if time.Now().After(deadline) {
			t.Fatal("the forward outlived its client while the target sat idle")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLocalPortForwardingDeliversTheWholeUploadWhenTheClientClosesRightAfterIt(t *testing.T) {
	t.Parallel()

	upload := bytes.Repeat([]byte("upload"), 1<<20)
	uploaded := make(chan int, 1)
	addr, client, cleanup := newTestSessionForwardingTo(t, func(conn net.Conn) {
		data, _ := io.ReadAll(conn)
		uploaded <- len(data)
	})
	defer cleanup()

	conn, err := client.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(upload); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case n := <-uploaded:
		if n != len(upload) {
			t.Fatalf("the target received %d of %d bytes", n, len(upload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the target never read the upload to EOF")
	}
}
