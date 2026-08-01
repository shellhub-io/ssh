package ssh

import (
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Containing the panic keeps the server alive, but the client is still owed an
// answer: a channel open that neither succeeds nor fails leaves it waiting on a
// reply that is never coming.
func TestPanickingChannelHandlerStillAnswersTheClient(t *testing.T) {
	srv := &Server{
		Handler: func(Session) {},
		ChannelHandlers: map[string]ChannelHandler{
			"session": func(*Server, *gossh.ServerConn, gossh.NewChannel, Context) {
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

	answered := make(chan error, 1)
	go func() {
		_, _, err := client.OpenChannel("session", nil)
		answered <- err
	}()

	select {
	case err := <-answered:
		if err == nil {
			t.Fatal("expected the channel open to be refused")
		}
		var openErr *gossh.OpenChannelError
		if !asOpenChannelError(err, &openErr) {
			t.Fatalf("expected an OpenChannelError, got %T: %v", err, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client was left waiting for a reply that never came")
	}
}

func asOpenChannelError(err error, target **gossh.OpenChannelError) bool {
	if e, ok := err.(*gossh.OpenChannelError); ok {
		*target = e
		return true
	}
	return false
}
