package soap

import (
	"errors"
	"testing"

	"github.com/m29h/xml"
)

func TestFaultError(t *testing.T) {
	fault := &Fault{
		Code:   "Server",
		String: "Internal server error",
		Actor:  "http://example.com/service",
	}

	expected := "soap fault: actor=http://example.com/service, code=Server, string=Internal server error"
	if fault.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, fault.Error())
	}
}

func TestFaultUnwrap(t *testing.T) {
	fault := &Fault{
		Code:   "Server",
		String: "Internal server error",
	}

	unwrapped := fault.Unwrap()
	if !errors.Is(unwrapped, ErrSoapFault) {
		t.Error("Fault.Unwrap() should return ErrSoapFault")
	}
}

func TestFaultDecodeDetail(t *testing.T) {
	type DetailStruct struct {
		XMLName xml.Name `xml:"detail"`
		Message string   `xml:"message"`
		Code    int      `xml:"code"`
	}

	fault := &Fault{
		Detail: details{
			Content: []byte(`<detail><message>Custom error</message><code>1001</code></detail>`),
		},
	}

	var detail DetailStruct
	err := fault.DecodeDetail(&detail)
	if err != nil {
		t.Errorf("DecodeDetail failed: %v", err)
	}

	if detail.Message != "Custom error" {
		t.Errorf("Expected message 'Custom error', got %q", detail.Message)
	}

	if detail.Code != 1001 {
		t.Errorf("Expected code 1001, got %d", detail.Code)
	}
}

func TestFaultDecodeDetailEmpty(t *testing.T) {
	fault := &Fault{
		Detail: details{
			Content: []byte{},
		},
	}

	var detail struct{}
	err := fault.DecodeDetail(&detail)
	if err != nil {
		t.Errorf("DecodeDetail with empty content should not fail: %v", err)
	}
}

func TestFaultDecodeDetailInvalidXML(t *testing.T) {
	fault := &Fault{
		Detail: details{
			Content: []byte(`<invalid><unclosed>`),
		},
	}

	var detail struct{}
	err := fault.DecodeDetail(&detail)
	if err == nil {
		t.Error("DecodeDetail with invalid XML should fail")
	}
}

func TestErrSoapFault(t *testing.T) {
	if ErrSoapFault == nil {
		t.Error("ErrSoapFault should not be nil")
	}

	if ErrSoapFault.Error() != "soap fault" {
		t.Errorf("Expected ErrSoapFault message 'soap fault', got %q", ErrSoapFault.Error())
	}
}
