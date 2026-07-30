package ingest

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	gofernet "github.com/fernet/fernet-go"
)

// TestFernetPythonRoundTrip verifies that Fernet tokens produced by fernet-go
// can be decrypted by Python's cryptography.fernet, and vice versa. This is the
// regression gate that turns "should be compatible per spec" into "verified
// compatible" — it must stay green through any future key rotation or library
// upgrade.
//
// Requires: python3 with the cryptography package installed.
func TestFernetPythonRoundTrip(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH — skipping cross-language round-trip test")
	}
	out, err := exec.Command(python, "-c", "import cryptography").CombinedOutput()
	if err != nil {
		t.Skipf("python3 cryptography not available (%s) — skipping", strings.TrimSpace(string(out)))
	}

	// Test-only key — 32 bytes, base64url-encoded. Never use in production.
	const testKey = "cE6nfJh6EBSuCCeGh_E0j_-4CpXKX-LDNrBpIgtTqEI="
	const plaintext = "source-ip-192.0.2.1"

	fk, err := newFernetKeys(testKey)
	if err != nil {
		t.Fatalf("newFernetKeys: %v", err)
	}

	// Direction 1: Go encrypts → Python decrypts.
	goToken, err := fk.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Go encrypt: %v", err)
	}
	pyDecrypted := runPythonScript(t, python, fmt.Sprintf(
		`from cryptography.fernet import Fernet; `+
			`print(Fernet(b%q).decrypt(b%q).decode(), end="")`,
		testKey, goToken,
	))
	if pyDecrypted != plaintext {
		t.Errorf("Python could not decrypt Go token:\n  got  %q\n  want %q", pyDecrypted, plaintext)
	}

	// Direction 2: Python encrypts → Go decrypts.
	pyToken := runPythonScript(t, python, fmt.Sprintf(
		`from cryptography.fernet import Fernet; `+
			`print(Fernet(b%q).encrypt(b%q).decode(), end="")`,
		testKey, plaintext,
	))
	k, err := gofernet.DecodeKey(testKey)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	// TTL of 0 disables expiry — acceptable for freshly-minted test tokens.
	goDecrypted := gofernet.VerifyAndDecrypt([]byte(strings.TrimSpace(pyToken)), 0, []*gofernet.Key{k})
	if goDecrypted == nil {
		t.Fatal("Go VerifyAndDecrypt returned nil — token invalid or key mismatch")
	}
	if string(goDecrypted) != plaintext {
		t.Errorf("Go decrypted wrong value:\n  got  %q\n  want %q", goDecrypted, plaintext)
	}

}

func runPythonScript(t *testing.T, python, script string) string {
	t.Helper()
	out, err := exec.Command(python, "-c", script).Output()
	if err != nil {
		t.Fatalf("python3 script failed: %v\nscript: %s", err, script)
	}
	return string(out)
}
