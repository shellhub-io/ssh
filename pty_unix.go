//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package ssh

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/charmbracelet/x/termios"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type impl struct {
	// Master is the master PTY file descriptor.
	Master *os.File

	// Slave is the slave PTY file descriptor. It is dropped once a command
	// owns the terminal, so it is nil for most of a session's life.
	Slave *os.File

	// name is the slave's path, kept because Name outlives the descriptor.
	name string
}

func (i *impl) IsZero() bool {
	return i.Master == nil && i.Slave == nil
}

// Name returns the name of the slave PTY, or the empty string when nothing was
// allocated. Pty() reports true while emulating, so callers reach these
// accessors on a Pty that has no files behind it.
//
// The name is answered from a copy taken at allocation: utmp bookkeeping asks
// for it after the session is over, by which point the descriptor is gone.
func (i *impl) Name() string {
	return i.name
}

// Read implements ptyInterface.
func (i *impl) Read(p []byte) (n int, err error) {
	if i.Master == nil {
		return 0, ErrUnsupported
	}
	return i.Master.Read(p)
}

// Write implements ptyInterface.
func (i *impl) Write(p []byte) (n int, err error) {
	if i.Master == nil {
		return 0, ErrUnsupported
	}
	return i.Master.Write(p)
}

// closeSlave drops the server's own reference to the slave.
//
// Until it is gone the server itself counts as a terminal user, so reading the
// master never reaches the end of the stream even after the command exits, and
// anything waiting for that end waits forever.
func (i *impl) closeSlave() error {
	if i.Slave == nil {
		return nil
	}

	err := i.Slave.Close()
	i.Slave = nil

	return err
}

func (i *impl) Close() error {
	var errs []error

	if i.Master != nil {
		errs = append(errs, i.Master.Close())
	}

	// Joined rather than returned early: closing the slave is what lets a read
	// parked on the master fail, so a master that refuses to close must not
	// cost us the close that unblocks everything else.
	errs = append(errs, i.closeSlave())

	return errors.Join(errs...)
}

func (i *impl) Resize(w int, h int) (rErr error) {
	if i.Master == nil {
		return ErrUnsupported
	}
	conn, err := i.Master.SyscallConn()
	if err != nil {
		return err
	}

	return conn.Control(func(fd uintptr) {
		rErr = termios.SetWinsize(int(fd), &unix.Winsize{
			Row: uint16(h),
			Col: uint16(w),
		})
	})
}

func (i *impl) start(c *exec.Cmd, cfg ptyStartConfig) error {
	if i.Slave == nil {
		// Assigning a nil *os.File here would hand the child a closed 0, 1 and
		// 2 and still report success, so the caller gets a command that answers
		// nothing rather than an error it can act on.
		return ErrUnsupported
	}

	c.Stdin, c.Stdout, c.Stderr = i.Slave, i.Slave, i.Slave
	if cfg.jobControl {
		if c.SysProcAttr == nil {
			c.SysProcAttr = &syscall.SysProcAttr{}
		}
		c.SysProcAttr.Setsid = true
		c.SysProcAttr.Setctty = true
	}
	if cfg.owner != nil {
		// Chown by path, not by fd: the slave's ownership lives on the devpts
		// node, and fchown on this descriptor does not reach it.
		if err := os.Chown(i.Slave.Name(), *cfg.owner, -1); err != nil {
			return err
		}
	}
	return c.Start()
}

func newPty(_ Context, _ string, win Window, modes ssh.TerminalModes) (_ impl, rErr error) {
	ptm, pts, err := pty.Open()
	if err != nil {
		return impl{}, err
	}

	conn, err := ptm.SyscallConn()
	if err != nil {
		return impl{}, err
	}

	if err := conn.Control(func(fd uintptr) {
		rErr = applyTerminalModesToFd(fd, win.Width, win.Height, modes)
	}); err != nil {
		return impl{}, err
	}

	return impl{Master: ptm, Slave: pts, name: pts.Name()}, rErr
}

func applyTerminalModesToFd(fd uintptr, width int, height int, modes ssh.TerminalModes) error {
	var ispeed, ospeed uint32
	ccs := map[termios.CC]uint8{}
	iflag := map[termios.I]bool{}
	oflag := map[termios.O]bool{}
	cflag := map[termios.C]bool{}
	lflag := map[termios.L]bool{}

	for op, value := range modes {
		switch op {
		case ssh.TTY_OP_ISPEED:
			ispeed = value
		case ssh.TTY_OP_OSPEED:
			ospeed = value
		default:
			cc, ok := sshToCc[op]
			if ok {
				ccs[cc] = uint8(value)
				continue
			}
			i, ok := sshToIflag[op]
			if ok {
				iflag[i] = value > 0
				continue
			}
			o, ok := sshToOflag[op]
			if ok {
				oflag[o] = value > 0
				continue
			}

			c, ok := sshToCflag[op]
			if ok {
				cflag[c] = value > 0
				continue
			}
			l, ok := sshToLflag[op]
			if ok {
				lflag[l] = value > 0
				continue
			}
		}
	}
	if err := termios.SetTermios(
		int(fd),
		ispeed,
		ospeed,
		ccs,
		iflag,
		oflag,
		cflag,
		lflag,
	); err != nil {
		return err
	}
	return termios.SetWinsize(int(fd), &unix.Winsize{
		Row: uint16(height),
		Col: uint16(width),
	})
}

var sshToCc = map[uint8]termios.CC{
	ssh.VINTR:    termios.INTR,
	ssh.VQUIT:    termios.QUIT,
	ssh.VERASE:   termios.ERASE,
	ssh.VKILL:    termios.KILL,
	ssh.VEOF:     termios.EOF,
	ssh.VEOL:     termios.EOL,
	ssh.VEOL2:    termios.EOL2,
	ssh.VSTART:   termios.START,
	ssh.VSTOP:    termios.STOP,
	ssh.VSUSP:    termios.SUSP,
	ssh.VWERASE:  termios.WERASE,
	ssh.VREPRINT: termios.RPRNT,
	ssh.VLNEXT:   termios.LNEXT,
	ssh.VDISCARD: termios.DISCARD,
	ssh.VSTATUS:  termios.STATUS,
	ssh.VSWTCH:   termios.SWTCH,
	ssh.VFLUSH:   termios.FLUSH,
	ssh.VDSUSP:   termios.DSUSP,
}

var sshToIflag = map[uint8]termios.I{
	ssh.IGNPAR:  termios.IGNPAR,
	ssh.PARMRK:  termios.PARMRK,
	ssh.INPCK:   termios.INPCK,
	ssh.ISTRIP:  termios.ISTRIP,
	ssh.INLCR:   termios.INLCR,
	ssh.IGNCR:   termios.IGNCR,
	ssh.ICRNL:   termios.ICRNL,
	ssh.IUCLC:   termios.IUCLC,
	ssh.IXON:    termios.IXON,
	ssh.IXANY:   termios.IXANY,
	ssh.IXOFF:   termios.IXOFF,
	ssh.IMAXBEL: termios.IMAXBEL,
}

var sshToOflag = map[uint8]termios.O{
	ssh.OPOST:  termios.OPOST,
	ssh.OLCUC:  termios.OLCUC,
	ssh.ONLCR:  termios.ONLCR,
	ssh.OCRNL:  termios.OCRNL,
	ssh.ONOCR:  termios.ONOCR,
	ssh.ONLRET: termios.ONLRET,
}

var sshToCflag = map[uint8]termios.C{
	ssh.CS7:    termios.CS7,
	ssh.CS8:    termios.CS8,
	ssh.PARENB: termios.PARENB,
	ssh.PARODD: termios.PARODD,
}

var sshToLflag = map[uint8]termios.L{
	ssh.IUTF8:   termios.IUTF8,
	ssh.ISIG:    termios.ISIG,
	ssh.ICANON:  termios.ICANON,
	ssh.ECHO:    termios.ECHO,
	ssh.ECHOE:   termios.ECHOE,
	ssh.ECHOK:   termios.ECHOK,
	ssh.ECHONL:  termios.ECHONL,
	ssh.NOFLSH:  termios.NOFLSH,
	ssh.TOSTOP:  termios.TOSTOP,
	ssh.IEXTEN:  termios.IEXTEN,
	ssh.ECHOCTL: termios.ECHOCTL,
	ssh.ECHOKE:  termios.ECHOKE,
	ssh.PENDIN:  termios.PENDIN,
	ssh.XCASE:   termios.XCASE,
}
