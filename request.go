package soap

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/m29h/xml"
)

// Request represents a single request to a SOAP service.
type Request struct {
	headers []HeaderBuilder
	method  string
	url     string
	action  string

	body interface{}
	resp interface{}
}

// NewRequest creates a SOAP request. This differs from a standard HTTP request in several ways.
// First, the SOAP library takes care of handling the envelope, so when the request is created
// the response and fault types are supplied so they can be properly parsed during envelope handling.
// Second, since we may perform WSSE signing on the request we do not supply a reader,
// instead the body is supplied here.
// If signing is desired, set the WSSE credentials on the request before passing it to the Client.
// NOTE: if custom SOAP headers are going to be supplied, they must be added before signing.
func NewRequest(action string, url string, body interface{}, respType interface{}) *Request {
	req := &Request{
		action: action,
		url:    url,
		body:   body,
		resp:   respType,
	}

	return req
}

// AddHeader adds the header argument to the list of elements set in the SOAP envelope Header element.
// This will be serialized to XML when the request is made to the service.
func (r *Request) AddHeader(header ...HeaderBuilder) {
	r.headers = append(r.headers, header...)
}

// serialize takes the data supplied in the request and serializes the SOAP data to the returned reader.
func (r *Request) serialize() (io.Reader, error) {
	envelope := NewEnvelope(r.body)

	for _, h := range r.headers {
		header, err := h(envelope.Body)
		if err != nil {
			return nil, err
		}
		envelope.AddHeaders(header)
	}

	envelopeEnc, err := xml.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile("request.xml", envelopeEnc, 0666); err != nil {
		log.Fatal(err)
	}

	return bytes.NewBuffer(envelopeEnc), nil
}

func (r *Request) httpRequest() (*http.Request, error) {
	buf, err := r.serialize()
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", r.url, buf)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	httpReq.Header.Add("SOAPAction", r.action)

	return httpReq, nil
}
