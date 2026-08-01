package ssh

import (
	"fmt"
	"testing"
)

// The library rewrites what the handler writes once a pty is requested, and
// whether it does is the difference between the two pty modes. A server that
// allocates its own pty gets that translation from the kernel, so a second one
// in software corrupts anything the kernel deliberately left alone: a bare \n
// from an application in raw mode, or a 0x0a inside binary output.
func TestPtyModeDecidesWhetherWritesAreRewritten(t *testing.T) {
	payloads := map[string]string{
		"bare LF":      "X\nY",
		"already CRLF": "X\r\nY",
		"binary 0x0a":  "\x1b[2J\n\xff",
		"no LF at all": "plain",
	}

	for name, payload := range payloads {
		t.Run("emulated/"+name, func(t *testing.T) {
			got := roundTrip(t, payload, true, nil)
			want := ptyWriterResult(payload)
			if got != want {
				t.Errorf("emulated pty: wrote %q, client got %q, expected %q", payload, got, want)
			}
		})

		t.Run("allocated/"+name, func(t *testing.T) {
			got := roundTrip(t, payload, true, AllocatePty())
			if got != payload {
				t.Errorf("allocated pty must not rewrite: wrote %q, client got %q", payload, got)
			}
		})

		t.Run("nopty/"+name, func(t *testing.T) {
			got := roundTrip(t, payload, false, nil)
			if got != payload {
				t.Errorf("no pty must not rewrite: wrote %q, client got %q", payload, got)
			}
		})
	}
}

// ptyWriterResult is what the emulating writer is documented to produce.
func ptyWriterResult(s string) string {
	var out []byte
	n, _ := NewPtyWriter(writerFunc(func(p []byte) (int, error) {
		out = append(out, p...)
		return len(p), nil
	})).Write([]byte(s))
	_ = n
	return string(out)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func roundTrip(t *testing.T, payload string, withPty bool, opt Option) string {
	t.Helper()

	srv := &Server{Handler: func(s Session) { fmt.Fprint(s, payload) }}
	if opt != nil {
		if err := srv.SetOption(opt); err != nil {
			t.Fatal(err)
		}
	}

	session, _, cleanup := newTestSession(t, srv, nil)
	defer cleanup()

	if withPty {
		if err := session.RequestPty("xterm", 40, 80, nil); err != nil {
			t.Fatal(err)
		}
	}

	got, err := session.Output("")
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}
