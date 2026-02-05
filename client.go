// Package soap provides a modular SOAP client with the WS-Security x.509 protocol support including features
// such as wsu:Timestamp and wsu:BinarySecurityToken, enabling SOAP calls against secured web services
package soap

import (
	"context"
	"errors"
	"net/http"
)

var (
	// ErrInvalidPEMFileSpecified is returned if the PEM file specified for WS signing is invalid
	ErrInvalidPEMFileSpecified = errors.New("invalid PEM key specified")
	// ErrEncryptedPEMFileSpecified is returnedd if the PEM file specified for WS signing is encrypted
	ErrEncryptedPEMFileSpecified = errors.New("encrypted PEM key specified")
	// ErrUnsupportedContentType is returned if we encounter a non-supported content type while querying
	ErrUnsupportedContentType = errors.New("unsupported content-type in response")
)

// Client is an opaque handle to a SOAP service.
type Client struct {
	url     string
	http    *http.Client
	headers []HeaderBuilder
}

// NewClient creates a new Client that will access a SOAP service.
// Requests made using this client will all be wrapped in a SOAP envelope.
// See https://www.w3schools.com/xml/xml_soap.asp for more details.
// The default HTTP client used has no timeout nor circuit breaking. Override with SettHTTPClient. You have been warned.
func NewClient(url string, soapHeaders ...HeaderBuilder) *Client {
	return &Client{
		url:     url,
		http:    http.DefaultClient,
		headers: soapHeaders,
	}
}

// SettHTTPClient sets a custom http.Client instance to be used for all communications (e.g. for seting timeouts)
func (c *Client) SettHTTPClient(http *http.Client) {
	c.http = http
}

// Do invokes the SOAP request using its internal parameters.
// The request argument is serialized to XML, and if the call is successful the received XML
// is deserialized into the response argument.
// Any errors that are encountered are returned.
// If a SOAP fault is detected, then the 'details' property of the SOAP envelope will be appended into the faultDetailType argument.
func (c *Client) Do(ctx context.Context, action string, request any, response any) error {

	req := NewRequest(action, c.url, request, response)
	req.AddHeader(c.headers...)
	httpReq, err := req.httpRequest()
	if err != nil {
		return err
	}

	httpResp, err := c.http.Do(httpReq.WithContext(ctx))
	if err != nil {
		return err
	}
	defer func() { _ = httpResp.Body.Close() }()

	resp := newResponse(httpResp, req)
	err = resp.deserialize()
	if err != nil {
		return err
	}
	if resp.Fault() != nil {
		return resp.Fault()
	}

	return nil
}
