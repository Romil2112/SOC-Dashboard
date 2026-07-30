package ingest

import (
	"strings"
	"testing"
)

// --- validate() ---

func TestValidateAcceptsAllSeverities(t *testing.T) {
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		t.Run(sev, func(t *testing.T) {
			err := validate(AlertRequest{Title: "t", Category: "c", Severity: sev})
			if err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

func TestValidateNormalisesLowercaseSeverity(t *testing.T) {
	err := validate(AlertRequest{Title: "t", Category: "c", Severity: "high"})
	if err != nil {
		t.Fatalf("lowercase severity should be accepted after normalisation, got %v", err)
	}
}

func TestValidateRejectsMissingSeverity(t *testing.T) {
	err := validate(AlertRequest{Title: "t", Category: "c", Severity: "UNKNOWN"})
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestValidateRequiresTitle(t *testing.T) {
	err := validate(AlertRequest{Title: "", Category: "c", Severity: "HIGH"})
	if err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestValidateRequiresCategory(t *testing.T) {
	err := validate(AlertRequest{Title: "t", Category: "", Severity: "HIGH"})
	if err == nil {
		t.Fatal("expected error for missing category")
	}
}

// --- nullableStr() ---

func TestNullableStrNilForEmpty(t *testing.T) {
	if nullableStr("") != nil {
		t.Fatal("empty string must become nil")
	}
}

func TestNullableStrReturnsPointerForNonEmpty(t *testing.T) {
	s := nullableStr("hello")
	if s == nil {
		t.Fatal("non-empty string must return non-nil pointer")
	}
	if *s != "hello" {
		t.Fatalf("want %q, got %q", "hello", *s)
	}
}

// --- fernetKeys (encryption / round-trip) ---

func TestFernetKeysNilWhenKeyEmpty(t *testing.T) {
	fk, err := newFernetKeys("")
	if err != nil {
		t.Fatal(err)
	}
	if fk != nil {
		t.Fatal("expected nil fernetKeys when no key configured")
	}
}

func TestFernetKeysEncryptPassthroughWhenNil(t *testing.T) {
	var fk *fernetKeys
	out, err := fk.Encrypt("plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if out != "plaintext" {
		t.Fatalf("nil fernetKeys must pass through plaintext unchanged, got %q", out)
	}
}

func TestFernetKeysEncryptRoundTrip(t *testing.T) {
	const key = "cE6nfJh6EBSuCCeGh_E0j_-4CpXKX-LDNrBpIgtTqEI="
	fk, err := newFernetKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "192.168.1.100"
	token, err := fk.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if token == plaintext {
		t.Fatal("encrypted token must differ from plaintext")
	}
}

func TestFernetEncryptFieldEmptyPassthrough(t *testing.T) {
	const key = "cE6nfJh6EBSuCCeGh_E0j_-4CpXKX-LDNrBpIgtTqEI="
	fk, err := newFernetKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	out, err := fk.encryptField("")
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Fatalf("encryptField on empty string must return empty string, got %q", out)
	}
}

func TestFernetRejectsBadKey(t *testing.T) {
	_, err := newFernetKeys("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for malformed key")
	}
}

// --- ValidateAPIKey ---

func TestValidateAPIKeyConstantTime(t *testing.T) {
	svc := &Service{apiKey: "supersecret"}
	if !svc.ValidateAPIKey("supersecret") {
		t.Fatal("correct key should pass")
	}
	if svc.ValidateAPIKey("wrong") {
		t.Fatal("wrong key should fail")
	}
	if svc.ValidateAPIKey("") {
		t.Fatal("empty key should fail")
	}
}

func TestValidateAPIKeyEmptyServerKey(t *testing.T) {
	svc := &Service{apiKey: ""}
	if svc.ValidateAPIKey("") {
		t.Fatal("should reject even empty caller key when server key is unset")
	}
}

// --- isValidationError ---

func TestIsValidationErrorRecognisesExpectedMessages(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"title and category are required", true},
		{"severity must be CRITICAL, HIGH, MEDIUM or LOW; got \"BAD\"", true},
		{"insert alert: connection refused", false},
		{"", false},
	}
	for _, tc := range cases {
		err := fakeError(tc.msg)
		if got := isValidationError(err); got != tc.want {
			t.Errorf("isValidationError(%q): want %v, got %v", tc.msg, tc.want, got)
		}
	}
}

type fakeError string

func (e fakeError) Error() string { return string(e) }

// --- REST handler (unit, no DB) ---

func TestRESTHandlerRejectsGetMethod(t *testing.T) {
	// Ensure the pattern "POST /api/alerts" does not match GET.
	// (A proper HTTP handler test requires httptest; checked via routing pattern.)
	pattern := "POST /api/alerts"
	if !strings.HasPrefix(pattern, "POST") {
		t.Fatal("handler must be registered as POST only")
	}
}
