package secret

import (
	"strings"
	"testing"
)

func TestHash_EmptyInput_KnownVector(t *testing.T) {
	// SHA-256("") base64url (no padding)
	const want = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	got := Hash("")
	if got != want {
		t.Fatalf("Hash(empty) = %q, want %q", got, want)
	}
	if strings.Contains(got, "=") {
		t.Fatalf("expected no padding in base64url: %q", got)
	}
}

func TestHash_ABC_KnownVector(t *testing.T) {
	// SHA-256("abc") base64url (no padding)
	const want = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
	got := Hash("abc")
	if got != want {
		t.Fatalf("Hash(abc) = %q, want %q", got, want)
	}
	if strings.Contains(got, "=") {
		t.Fatalf("expected no padding in base64url: %q", got)
	}
}

func TestHash_NoPaddingForCommonInputs(t *testing.T) {
	for _, in := range []string{"foo", "bar", "baz", "hello", "world"} {
		h := Hash(in)
		if strings.Contains(h, "=") {
			t.Fatalf("hash %q contains padding '=' for input %q", h, in)
		}
	}
}

func TestHash_DifferentInputs_ProduceDifferentHashes(t *testing.T) {
	h1 := Hash("a")
	h2 := Hash("b")
	if h1 == h2 {
		t.Fatalf("expected different hashes for different inputs: %q vs %q", h1, h2)
	}
}

func TestEqual_MatchesIdentical(t *testing.T) {
	h := Hash("same")
	if !Equal(h, h) {
		t.Fatalf("Equal should return true for identical strings")
	}
}

func TestEqual_DifferentValues(t *testing.T) {
	h1 := Hash("left")
	h2 := Hash("right")
	if Equal(h1, h2) {
		t.Fatalf("Equal should return false for different values")
	}
}

func TestEqual_DifferentLengths(t *testing.T) {
	// Not real hashes, but different lengths should short-circuit to false.
	if Equal("short", "a little bit longer") {
		t.Fatalf("Equal should return false for different lengths")
	}
}

func TestEqual_SameContentDifferentInstances(t *testing.T) {
	// Ensure true for equal strings created separately.
	h1 := Hash("repeatable")
	h2 := Hash("repeatable")
	if !Equal(h1, h2) {
		t.Fatalf("Equal should return true for equal content from separate calls")
	}
}
