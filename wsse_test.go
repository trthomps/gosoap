package soap

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/m29h/xml"
)

type testBody struct {
	XMLName struct{} `xml:"test:TestBody"`
	WsuID   string   `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

func TestNewWSSEAuthInfo(t *testing.T) {
	// Test creating WSSEAuthInfo with certificate path
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Fatalf("NewWSSEAuthInfo failed: %v", err)
	}

	if authInfo == nil {
		t.Fatal("Expected non-nil WSSEAuthInfo")
	}

	if authInfo.signatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("Expected default signature algorithm SHA256WithRSA, got %v", authInfo.signatureAlgorithm)
	}

	if authInfo.digestMethod != crypto.SHA256 {
		t.Errorf("Expected default digest method SHA256, got %v", authInfo.digestMethod)
	}
}

func TestNewWSSEAuthInfoWithOptions(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
		WithWSSEAuthInfoSignatureAlgorithm(x509.SHA512WithRSA),
		WithWSSEAuthInfoDigestMethod(crypto.SHA512),
	)
	if err != nil {
		t.Fatalf("NewWSSEAuthInfo with options failed: %v", err)
	}

	if authInfo.signatureAlgorithm != x509.SHA512WithRSA {
		t.Errorf("Expected signature algorithm SHA512WithRSA, got %v", authInfo.signatureAlgorithm)
	}

	if authInfo.digestMethod != crypto.SHA512 {
		t.Errorf("Expected digest method SHA512, got %v", authInfo.digestMethod)
	}
}

func TestNewWSSEAuthInfoWithStringOptions(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
		WithWSSEAuthInfoSignatureAlgorithmString("rsa-sha384"),
		WithWSSEAuthInfoDigestMethodString("sha384"),
	)
	if err != nil {
		t.Fatalf("NewWSSEAuthInfo with string options failed: %v", err)
	}

	if authInfo.signatureAlgorithm != x509.SHA384WithRSA {
		t.Errorf("Expected signature algorithm SHA384WithRSA, got %v", authInfo.signatureAlgorithm)
	}

	if authInfo.digestMethod != crypto.SHA384 {
		t.Errorf("Expected digest method SHA384, got %v", authInfo.digestMethod)
	}
}

func TestNewWSSEAuthInfoWithTLSCert(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCert(cert),
	)
	if err != nil {
		t.Fatalf("NewWSSEAuthInfo with TLS cert failed: %v", err)
	}

	if authInfo == nil {
		t.Fatal("Expected non-nil WSSEAuthInfo")
	}
}

func TestNewWSSEAuthInfoErrors(t *testing.T) {
	// Test with invalid certificate path
	_, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("nonexistent.pem", "nonexistent.pem"),
	)
	if err == nil {
		t.Error("Expected error with invalid certificate path")
	}

	// Test with no certificate
	_, err = NewWSSEAuthInfo()
	if err == nil {
		t.Error("Expected error when no certificate is provided")
	}
}

func TestX509SignatureAlgorithmFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected x509.SignatureAlgorithm
		hasError bool
	}{
		{"rsa-sha1", x509.SHA1WithRSA, false},
		{"rsa-sha256", x509.SHA256WithRSA, false},
		{"rsa-sha384", x509.SHA384WithRSA, false},
		{"rsa-sha512", x509.SHA512WithRSA, false},
		{"ecdsa-sha256", x509.ECDSAWithSHA256, false},
		{"invalid", 0, true},
	}

	for _, test := range tests {
		result, err := x509SignatureAlgorithmFromString(test.input)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %q", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %q: %v", test.input, err)
			}
			if result != test.expected {
				t.Errorf("For input %q, expected %v, got %v", test.input, test.expected, result)
			}
		}
	}
}

func TestCryptoHashFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected crypto.Hash
		hasError bool
	}{
		{"sha1", crypto.SHA1, false},
		{"sha256", crypto.SHA256, false},
		{"sha384", crypto.SHA384, false},
		{"sha512", crypto.SHA512, false},
		{"invalid", 0, true},
	}

	for _, test := range tests {
		result, err := cryptoHashFromString(test.input)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %q", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %q: %v", test.input, err)
			}
			if result != test.expected {
				t.Errorf("For input %q, expected %v, got %v", test.input, test.expected, result)
			}
		}
	}
}

func TestCryptoHashFromX509SignatureAlgorithm(t *testing.T) {
	tests := []struct {
		input    x509.SignatureAlgorithm
		expected crypto.Hash
	}{
		{x509.SHA1WithRSA, crypto.SHA1},
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.ECDSAWithSHA256, crypto.SHA256},
	}

	for _, test := range tests {
		result := cryptoHashFromX509SignatureAlgorithm(test.input)
		if result != test.expected {
			t.Errorf("For input %v, expected %v, got %v", test.input, test.expected, result)
		}
	}
}

func TestSoapTime(t *testing.T) {
	now := time.Now()
	soapTime := soapTimeFromTime(now)

	// Test String method
	str := soapTime.String()
	if str == "" {
		t.Error("soapTime.String() should not be empty")
	}

	// Test that we can parse it back
	parsed, err := time.Parse(RFC3339milli, str)
	if err != nil {
		t.Errorf("Failed to parse soapTime string: %v", err)
	}

	// Should be within a second of original time (accounting for millisecond precision)
	diff := parsed.Sub(now)
	if diff > time.Second || diff < -time.Second {
		t.Errorf("Parsed time differs too much from original: %v", diff)
	}
}

func TestSoapTimeNow(t *testing.T) {
	before := time.Now()
	soapTime := soapTimeNow()
	after := time.Now()

	timeValue := time.Time(soapTime)
	if timeValue.Before(before) || timeValue.After(after) {
		t.Error("soapTimeNow() should return current time")
	}
}

func TestGetWsuID(t *testing.T) {
	id1 := getWsuID()
	id2 := getWsuID()

	if id1 == id2 {
		t.Error("getWsuID() should return unique IDs")
	}

	if !strings.HasPrefix(id1, "WSSE") {
		t.Errorf("Expected ID to start with 'WSSE', got %q", id1)
	}
}

func TestAddSignature(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	body := &testBody{Value: "test content"}

	err = authInfo.addSignature(body)
	if err != nil {
		t.Fatalf("addSignature failed: %v", err)
	}

	if body.WsuID == "" {
		t.Error("addSignature should set WsuID")
	}

	if len(authInfo.sigRef) != 1 {
		t.Errorf("Expected 1 signature reference, got %d", len(authInfo.sigRef))
	}
}

func TestAddSignatureErrors(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	// Test with non-pointer
	var body testBody
	err = authInfo.addSignature(body)
	if err == nil {
		t.Error("addSignature should fail with non-pointer")
	}

	// Test with struct without WsuID field
	type badBody struct {
		Value string
	}
	bad := &badBody{Value: "test"}
	err = authInfo.addSignature(bad)
	if err == nil {
		t.Error("addSignature should fail with struct without WsuID field")
	}
}

func TestSecurityHeader(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	body := &testBody{Value: "test content"}

	security, err := authInfo.securityHeader(body)
	if err != nil {
		t.Fatalf("securityHeader failed: %v", err)
	}

	if security.MustUnderstand != 1 {
		t.Error("Security header should have mustUnderstand=1")
	}

	if security.BinarySecurityToken.Value == "" {
		t.Error("BinarySecurityToken should have a value")
	}

	if security.Signature.SignatureValue == "" {
		t.Error("Signature should have a value")
	}

	if security.Timestamp.WsuID == "" {
		t.Error("Timestamp should have WsuID")
	}
}

func TestSecurityHeaderEmptyBody(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	_, err = authInfo.securityHeader(nil)
	if err != ErrUnableToSignEmptyEnvelope {
		t.Errorf("Expected ErrUnableToSignEmptyEnvelope, got %v", err)
	}
}

func TestHeaderBuilder(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	headerBuilder := authInfo.Header()
	if headerBuilder == nil {
		t.Error("Header() should return a HeaderBuilder")
	}

	body := &testBody{Value: "test content"}
	header, err := headerBuilder(body)
	if err != nil {
		t.Fatalf("HeaderBuilder failed: %v", err)
	}

	securityHeader, ok := header.(security)
	if !ok {
		t.Error("HeaderBuilder should return a security header")
	}

	if securityHeader.MustUnderstand != 1 {
		t.Error("Security header should have mustUnderstand=1")
	}
}

func TestCanonicalize(t *testing.T) {
	// xml.Marshal encodes newlines as &#xA; character references.
	// Exclusive C14N requires these to be decoded to literal bytes (0x0A).
	body := &testBody{Value: "test\n\n"}
	raw, err := xml.Marshal(body)
	if err != nil {
		t.Fatalf("xml.Marshal failed: %v", err)
	}

	if !bytes.Contains(raw, []byte("&#xA;")) {
		t.Fatal("Expected xml.Marshal to produce &#xA; character references for newlines")
	}

	canonical, err := canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize failed: %v", err)
	}

	if bytes.Contains(canonical, []byte("&#xA;")) {
		t.Error("Canonicalized output should not contain &#xA; character references; newlines must be literal bytes")
	}

	if !bytes.Contains(canonical, []byte("test\n\n")) {
		t.Error("Canonicalized output should contain literal newline bytes")
	}
}

func TestAddSignatureDigestUsesCanonicalForm(t *testing.T) {
	authInfo, err := NewWSSEAuthInfo(
		WithWSSEAuthInfoCertPath("testdata/cert.pem", "testdata/key.pem"),
	)
	if err != nil {
		t.Skipf("Skipping test - cert files not available: %v", err)
	}

	// Use content with newlines, which triggers the &#xA; encoding issue.
	body := &testBody{Value: "test\n\n"}

	err = authInfo.addSignature(body)
	if err != nil {
		t.Fatalf("addSignature failed: %v", err)
	}

	if len(authInfo.sigRef) != 1 {
		t.Fatalf("Expected 1 signature reference, got %d", len(authInfo.sigRef))
	}
	actualDigest := authInfo.sigRef[0].DigestValue.Value

	// Compute the expected digest from the canonicalized XML.
	enc, err := xml.Marshal(body)
	if err != nil {
		t.Fatalf("xml.Marshal failed: %v", err)
	}
	canonical, err := canonicalize(enc)
	if err != nil {
		t.Fatalf("canonicalize failed: %v", err)
	}
	h := sha256.Sum256(canonical)
	expectedDigest := base64.StdEncoding.EncodeToString(h[:])

	if actualDigest != expectedDigest {
		t.Errorf("Digest mismatch: addSignature produced %q, expected %q (from canonicalized XML)", actualDigest, expectedDigest)
	}

	// Also verify the digest does NOT match a hash of the raw (non-canonical) marshalled bytes.
	// This confirms the canonicalization is actually doing something.
	rawHash := sha256.Sum256(enc)
	rawDigest := base64.StdEncoding.EncodeToString(rawHash[:])

	if actualDigest == rawDigest {
		t.Error("Digest should differ from raw xml.Marshal output; canonicalization is not being applied")
	}
}
