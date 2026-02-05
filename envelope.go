package soap

import (
	"errors"
	"fmt"

	"github.com/m29h/xml"
)

const soapEnvNS = "http://schemas.xmlsoap.org/soap/envelope/"

var (
	// ErrEnvelopeMisconfigured is returned if we attempt to deserialize a SOAP envelope without a type to deserialize the body or fault into.
	ErrEnvelopeMisconfigured = errors.New("envelope content or fault pointer empty")
)

// Envelope is a SOAP envelope.
type Envelope struct {
	// XMLName is the serialized name of this object.
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`

	Header *Header
	Body   *Body
}

// HeaderBuilder is a function that takes an interface to the body and
// returns the finished header and an error
type HeaderBuilder func(body any) (any, error)

func init() {

}

// NewEnvelope creates a new SOAP Envelope with the specified data as the content to serialize or deserialize.
// It defaults to a fault struct with no detail type. Content of the fault detail is wrapped into the error type.
// Headers are assumed to be omitted unless explicitly added via AddHeaders()
func NewEnvelope(content interface{}) *Envelope {
	switch v := content.(type) {
	case []any: // content array with multiple elements
		return &Envelope{Body: &Body{Content: v}}
	}
	// single element body content
	return &Envelope{Body: &Body{Content: []any{content}}}
}

// AddHeaders adds additional headers to be serialized to the resulting SOAP envelope.
func (e *Envelope) AddHeaders(elems ...any) {
	if e.Header == nil {
		e.Header = &Header{}
	}

	e.Header.Headers = append(e.Header.Headers, elems...)
}

// Header is a SOAP envelope header.
type Header struct {
	// XMLName is the serialized name of this object.
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	// Headers is an array of envelope headers to send.
	Headers []interface{} `xml:",omitempty"`
}

// Body is a SOAP envelope body.
type Body struct {
	// XMLName is the serialized name of this object.
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	// XMLNSWsu is the SOAP WS-Security utility namespace.
	WsuID string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`

	// Fault is a SOAP fault we may detect in a response.
	Fault *Fault `xml:",omitempty"`
	// Body is a SOAP request or response body.
	Content []interface{} `xml:",omitempty"`
}

// UnmarshalXML is an overridden deserialization routine used to decode a SOAP envelope body.
// The elements are read from the decoder d, starting at the element start. The contents of the decode are stored
// in the invoking body b. Any errors encountered are returned.
func (b *Body) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return ErrEnvelopeMisconfigured
	}
	for _, c := range b.Content {
		if c == nil {
			return ErrEnvelopeMisconfigured
		}
	}
	b.Fault = &Fault{}

	elementDone := make([]bool, len(b.Content))
tokens:
	for {
		token, err := d.Token()
		if err != nil {
			return err
		} else if token == nil {
			return nil
		}

		switch elem := token.(type) {
		case xml.StartElement:
			// If the start element is a fault decode it as a fault, otherwise parse it as content.
			var err error
			if elem.Name.Space == soapEnvNS && elem.Name.Local == "Fault" {
				err = d.DecodeElement(b.Fault, &elem)
				if err != nil {
					return err
				}
				b.Content = nil
			} else {
				for i := range b.Content {
					if elementDone[i] {
						continue
					}
					err = d.DecodeElement(b.Content[i], &elem)
					if err != nil {
						continue
					} else {
						elementDone[i] = true
						b.Fault = nil
						continue tokens
					}
				}
				if err != nil {
					return err
				}
				return fmt.Errorf("received token %s %s in body but have no content field to unmarshal to", elem.Name.Space, elem.Name.Local)
			}
		case xml.EndElement:
			// We expect the Body to have a single entry, so once we encounter the end element we're done.
			return nil
		}
	}
}
