package ssh

import (
	"encoding/binary"
	"testing"
)

func TestParseStringRejectsOverflowingLength(t *testing.T) {
	t.Parallel()

	// A length near MaxUint32 makes 4+length wrap around, so a bounds check
	// written that way accepts the payload and slices out of range.
	in := make([]byte, 8)
	binary.BigEndian.PutUint32(in, 0xFFFFFFFF)

	if _, _, ok := parseString(in); ok {
		t.Fatal("expected an oversized length to be rejected")
	}
}

func TestParsePtyRequestRejectsOverflowingTerm(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload, 0xFFFFFFFF)

	if _, ok := parsePtyRequest(payload); ok {
		t.Fatal("expected a malformed pty-req to be rejected")
	}
}

func TestParseStringRoundTrip(t *testing.T) {
	t.Parallel()

	in := make([]byte, 4, 9)
	binary.BigEndian.PutUint32(in, 5)
	in = append(in, "xterm"...)

	out, rest, ok := parseString(in)
	if !ok {
		t.Fatal("expected a well-formed string to parse")
	}
	if out != "xterm" {
		t.Fatalf("expected %q, got %q", "xterm", out)
	}
	if len(rest) != 0 {
		t.Fatalf("expected no remainder, got %q", rest)
	}
}
