package soap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/m29h/xml"
)

var (
	// a fault body element was received
	ErrSoapFault = errors.New("soap fault")
)

// Fault is a SOAP fault code.
type Fault struct {
	// XMLName is the serialized name of this object.
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`

	// DetailInternal is a handle to the internal fault detail type. Do not directly access;
	// this is made public only to allow for XML deserialization.
	// Use the Detail() method instead.
	DetailInternal *faultDetail `xml:"detail,omitempty"`
}

// NewFault returns a new XML fault struct
func NewFault() *Fault {
	return &Fault{DetailInternal: &faultDetail{}}
}

// Error satisfies the Error() interface allowing us to return a fault as an error.
func (f *Fault) Error() string {
	s := fmt.Sprintf("soap fault: %s (%s)", f.Code, f.String)
	if f.DetailInternal == nil {
		return s
	}
	if f.DetailInternal.Content == "" {
		return s
	}
	s += fmt.Sprintf("\n%s", strings.TrimSpace(f.DetailInternal.Content))
	return s
}

func (f *Fault) Unwrap() error {
	return ErrSoapFault
}

// faultDetail is an implementation detail of how we parse out the optional detail element of the XML fault.
type faultDetail struct {
	Content string `xml:",innerxml"`
}

// UnmarshalXML is an overridden deserialization routine used to decode a SOAP fault.
// The elements are read from the decoder d, starting at the element start. The contents of the decode are stored
// in the invoking fault f. Any errors encountered are returned.
func (f *faultDetail) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	fd := struct {
		Content string `xml:",innerxml"`
	}{}
	if err := d.DecodeElement(&fd, &start); err != nil {
		return err
	}

	f.Content = fd.Content
	return nil
}
