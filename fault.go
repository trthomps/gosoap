package soap

import (
	"errors"
	"fmt"

	"github.com/m29h/xml"
)

var (
	// ErrSoapFault indicates a fault body element was received
	ErrSoapFault = errors.New("soap fault")
)

type details struct {
	Content []byte `xml:",innerxml"`
}

// Fault is a SOAP fault code.
type Fault struct {
	// XMLName is the serialized name of this object.
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string  `xml:"faultcode,omitempty"`
	String string  `xml:"faultstring,omitempty"`
	Actor  string  `xml:"faultactor,omitempty"`
	Detail details `xml:"detail"`
}

// Error satisfies the Error() interface allowing us to return a fault as an error.
func (f *Fault) Error() string {
	s := fmt.Sprintf("soap fault: actor=%s, code=%s, string=%s", f.Actor, f.Code, f.String)
	return s
}

func (f *Fault) Unwrap() error {
	return ErrSoapFault
}

func (f *Fault) DecodeDetail(v any) error {
	if len(f.Detail.Content) == 0 {
		return nil
	}
	return xml.Unmarshal(f.Detail.Content, v)
}
