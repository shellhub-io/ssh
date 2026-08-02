package ssh

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/anmitsu/go-shlex"
	gossh "golang.org/x/crypto/ssh"
)

// Session provides access to information about an SSH session and methods
// to read and write to the SSH channel with an embedded Channel interface from
// crypto/ssh.
//
// When Command() returns an empty slice, the user requested a shell. Otherwise
// the user is performing an exec with those command arguments.
//
// TODO: Signals.
type Session interface {
	gossh.Channel

	// User returns the username used when establishing the SSH connection.
	User() string

	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr

	// Environ returns a copy of strings representing the environment set by the
	// user for this session, in the form "key=value".
	Environ() []string

	// Exit sends an exit status. It leaves the channel open so any output the
	// command has not delivered yet still gets through; the session is closed
	// once its handler returns.
	Exit(code int) error

	// Command returns a shell parsed slice of arguments that were provided by the
	// user. Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	Command() []string

	// RawCommand returns the exact command that was provided by the user.
	RawCommand() string

	// Subsystem returns the subsystem requested by the user.
	Subsystem() string

	// PublicKey returns the PublicKey used to authenticate. If a public key was not
	// used it will return nil.
	PublicKey() PublicKey

	// Context returns the connection's context. The returned context is always
	// non-nil and holds the same data as the Context passed into auth
	// handlers and callbacks.
	//
	// The context is canceled when the client's connection closes or I/O
	// operation fails.
	Context() Context

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers via the Context.
	Permissions() Permissions

	// EmulatedPty returns true if the session is emulating a PTY using PtyWriter.
	EmulatedPty() bool

	// Pty returns PTY information, a channel of window size changes, and a boolean
	// of whether or not a PTY was accepted for this session.
	Pty() (Pty, <-chan Window, bool)

	// Signals registers a channel to receive signals sent from the client. The
	// channel must handle signal sends or it will block the SSH request loop.
	// Registering nil will unregister the channel from signal sends. During the
	// time no channel is registered signals are buffered up to a reasonable amount.
	// If there are buffered signals when a channel is registered, they will be
	// sent in order on the channel immediately after registering.
	Signals(c chan<- Signal)

	// Break regisers a channel to receive notifications of break requests sent
	// from the client. The channel must handle break requests, or it will block
	// the request handling loop. Registering nil will unregister the channel.
	// During the time that no channel is registered, breaks are ignored.
	Break(c chan<- bool)
}

// maxSigBufSize is how many signals will be buffered
// when there is no signal channel specified.
const maxSigBufSize = 128

// DefaultSessionHandler is the default handler for the "session" channel type.
func DefaultSessionHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		slog.Warn("ssh: failed to accept session channel", "err", err)
		return
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           srv.Handler,
		ptyCb:             srv.PtyCallback,
		ptyHandler:        srv.PtyHandler,
		sessReqCb:         srv.SessionRequestCallback,
		subsystemHandlers: srv.SubsystemHandlers,
		ctx:               ctx,
	}
	ctx.SetValue(ContextKeySession, sess)
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	gossh.Channel
	conn              *gossh.ServerConn
	handler           Handler
	subsystemHandlers map[string]SubsystemHandler
	handled           bool
	exited            bool
	pty               *Pty
	winch             chan Window
	env               []string
	ptyCb             PtyCallback
	ptyHandler        PtyHandler
	sessReqCb         SessionRequestCallback
	rawCmd            string
	subsystem         string
	ctx               Context
	sigCh             chan<- Signal
	sigBuf            []Signal
	breakCh           chan<- bool
}

func (sess *session) Stderr() io.ReadWriter {
	if sess.pty != nil && sess.EmulatedPty() {
		return NewPtyReadWriter(sess.Channel.Stderr())
	}
	return sess.Channel.Stderr()
}

func (sess *session) Write(p []byte) (int, error) {
	if sess.pty != nil && sess.EmulatedPty() {
		return NewPtyWriter(sess.Channel).Write(p)
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() PublicKey {
	sessionkey := sess.ctx.Value(ContextKeyPublicKey)
	if sessionkey == nil {
		return nil
	}
	return sessionkey.(PublicKey)
}

func (sess *session) Permissions() Permissions {
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(ContextKeyPermissions).(*Permissions)
	return *perms
}

func (sess *session) Context() Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, gossh.Marshal(&status))
	if err != nil {
		return err
	}

	// Closing here would cut off output the command wrote just before exiting
	// and that has not been copied out yet. Whoever ends the session closes it.
	//
	// https://datatracker.ietf.org/doc/html/rfc4254#section-6.10
	return nil
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shlex.Split(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) EmulatedPty() bool {
	return sess.ctx.Value(contextKeyEmulatePty) == true
}

func (sess *session) Pty() (Pty, <-chan Window, bool) {
	sess.Lock()
	defer sess.Unlock()
	if sess.pty != nil && (sess.EmulatedPty() || !sess.pty.IsZero()) {
		return *sess.pty, sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

// releaseUnhandledPty closes the pty unless a handler took it over. Once shell
// or exec is accepted the handler goroutine owns it and releases it itself, and
// closing here as well can pull the slave out from under a command that is
// still starting. A pty-req that never became a shell has no other owner.
func (sess *session) releaseUnhandledPty(closer func() error) {
	if !sess.handled {
		_ = closer()
	}
}

// ptyDrainTimeout bounds the wait for a pty's remaining output. A process the
// command left running behind it holds the terminal open, and the copy would
// otherwise have nothing to stop on.
const ptyDrainTimeout = 5 * time.Second

// drainPty releases the server's slave descriptor and waits for what the pty
// still holds to reach the channel.
//
// Dropping the slave is what ends the copy: while the server keeps it, reading
// the master never reaches the end of the stream, not even once the command has
// exited. Without the wait the close that follows discards whatever has not
// been copied out, which is most of a burst written just before exiting.
func (sess *session) drainPty(drained <-chan struct{}) {
	if sess.pty == nil || sess.pty.IsZero() {
		return
	}

	_ = sess.pty.closeSlave()

	if drained == nil {
		return
	}

	select {
	case <-drained:
	case <-time.After(ptyDrainTimeout):
		slog.Warn("ssh: gave up waiting for the pty to drain", "timeout", ptyDrainTimeout)
	}
}

// finish ends a session a handler took over.
//
// The order is the point, and it is only possible because Exit stopped closing
// the channel. Exit is also a no-op once the handler reported a status of its
// own, so a handler that exits with a code keeps it.
func (sess *session) finish(drained <-chan struct{}) {
	sess.drainPty(drained)
	_ = sess.Exit(0)
	_ = sess.CloseWrite()
	_ = sess.Close()

	if sess.pty != nil && !sess.pty.IsZero() {
		_ = sess.pty.Close()
	}
}

func (sess *session) handleRequests(reqs <-chan *gossh.Request) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}

			payload := struct{ Value string }{}
			_ = gossh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			if sess.handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			sess.handled = true
			_ = req.Reply(true, nil)

			go func() {
				var drained chan struct{}

				// Registered before the recover so it runs after it: a handler
				// that panics still has to leave the channel closed and the pty
				// released, or the client waits on a session nobody will answer.
				defer func() { sess.finish(drained) }()
				defer recoverAndLog("panic in session handler", nil, func() {
					_ = sess.Exit(1)
				})

				if sess.pty != nil && !sess.pty.IsZero() {
					drained = make(chan struct{})

					go func() {
						defer recoverAndLog("panic copying to pty", nil, nil)
						_, _ = io.Copy(sess.pty, sess)
					}()
					go func() {
						defer close(drained)
						defer recoverAndLog("panic copying from pty", nil, nil)

						// A write that fails here is output the client never
						// saw, so it is worth a line even though nothing can
						// act on it.
						if _, err := io.Copy(sess, sess.pty); err != nil {
							slog.Warn("ssh: pty output did not reach the client", "err", err)
						}
					}()
				}

				sess.handler(sess)
			}()
		case "subsystem":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}

			payload := struct{ Value string }{}
			_ = gossh.Unmarshal(req.Payload, &payload)
			sess.subsystem = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[payload.Value]
			if handler == nil {
				handler = sess.subsystemHandlers["default"]
			}
			if handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			sess.handled = true
			_ = req.Reply(true, nil)

			go func() {
				// A subsystem can be preceded by a pty-req, and accepting the
				// request makes this goroutine its owner: releaseUnhandledPty
				// steps aside for exactly that reason, so without the release in
				// finish the pair survives the session and the pts stays taken.
				defer func() { sess.finish(nil) }()
				defer recoverAndLog("panic in subsystem handler", nil, func() {
					_ = sess.Exit(1)
				})
				handler(sess)
			}()
		case "env":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			_ = gossh.Unmarshal(req.Payload, &kv)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			_ = req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			_ = gossh.Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "pty-req":
			if sess.handled || sess.pty != nil {
				_ = req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				_ = req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
					_ = req.Reply(false, nil)
					continue
				}
			}

			// The request loop writes pty and winch while the user's handler
			// reads them through Pty() on its own goroutine.
			sess.Lock()
			sess.pty = &ptyReq
			sess.winch = make(chan Window, 1)
			sess.Unlock()
			sess.winch <- ptyReq.Window

			if sess.ptyHandler != nil {
				closer, err := sess.ptyHandler(sess.ctx, sess, ptyReq)
				if err != nil {
					// Undo the pty-req setup, or window-change keeps sending on
					// a winch nobody drains and wedges the loop.
					sess.Lock()
					sess.pty = nil
					sess.Unlock()
					close(sess.winch)
					_ = req.Reply(false, nil)
					continue
				}

				defer sess.releaseUnhandledPty(closer) //nolint:staticcheck // intentional: runs when req channel closes

				if !sess.EmulatedPty() && !sess.pty.IsZero() {
					go func() {
						defer recoverAndLog("panic resizing pty", nil, nil)
						for win := range sess.winch {
							if err := resizePty(sess, win); err != nil {
								// TODO: handle error
								continue
							}
						}
					}()
				}
			}

			defer func() { //nolint:staticcheck // intentional: runs when req channel closes
				// when reqs is closed
				close(sess.winch)
			}()
			_ = req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				_ = req.Reply(false, nil)
				continue
			}
			win, _, ok := parseWindow(req.Payload)
			if ok {
				sess.Lock()
				sess.pty.Window = win
				sess.Unlock()
				// A queued size nobody took is stale, and blocking on it wedges
				// the loop. This is the only sender, so the send cannot block.
				select {
				case <-sess.winch:
				default:
				}
				sess.winch <- win
			}
			_ = req.Reply(ok, nil)
		case agentRequestType:
			// TODO: option/callback to allow agent forwarding
			SetAgentRequested(sess.ctx)
			_ = req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			_ = req.Reply(ok, nil)
			sess.Unlock()
		default:
			slog.Debug("ssh: unknown session request", "type", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (sess *session) ptyAllocate(term string, win Window, modes gossh.TerminalModes) (func() error, error) {
	p, err := newPty(sess.ctx, term, win, modes)
	if err != nil {
		return nil, err
	}

	sess.pty = &Pty{
		Term:   term,
		Window: win,
		Modes:  modes,
		impl:   p,
	}

	return p.Close, nil
}

func resizePty(sess *session, win Window) error {
	if sess.pty == nil {
		return nil
	}

	return sess.pty.Resize(win.Width, win.Height)
}
