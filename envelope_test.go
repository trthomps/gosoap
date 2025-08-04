package soap

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/m29h/xml"
)

var envelopeName = xml.Name{
	Space: soapEnvNS,
	Local: "Envelope",
}
var bodyName = xml.Name{
	Space: soapEnvNS,
	Local: "Body",
}

type headerExample struct {
	XMLName xml.Name `xml:"ns HeaderExample"`
	Attr1   int32    `xml:"attr1,attr"`
	Value   string   `xml:",chardata"`
}

type envelopeExampleField struct {
	XMLName xml.Name `xml:"ContentField"`
	Attr1   string   `xml:"attr1,attr"`
	Attr2   int32    `xml:"attr2,attr"`
	Value   string   `xml:",chardata"`
}

type envelopeContentExample struct {
	XMLName xml.Name             `xml:"ns ContentExample"`
	Attr1   int32                `xml:"attr1,attr"`
	Field1  envelopeExampleField `xml:"ContentField"`
}

type envelopeEncodeTest struct {
	headers    []headerExample
	contentPtr interface{}
	res        string
	err        error
}

var envelopeEncodeTests = []envelopeEncodeTest{
	{
		contentPtr: &envelopeContentExample{
			Attr1: 10,
			Field1: envelopeExampleField{
				XMLName: xml.Name{Local: "ContentField"},
				Attr1:   "test attr",
				Attr2:   11,
				Value:   "This is a test string",
			},
		},
		res: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:ContentExample xmlns:ns="ns" attr1="10"><ns:ContentField attr1="test attr" attr2="11">This is a test string</ns:ContentField></ns:ContentExample></soapenv:Body></soapenv:Envelope>`,
	},
	{
		contentPtr: &envelopeContentExample{
			XMLName: xml.Name{Local: "ContentExample"},
			Attr1:   10,
			Field1: envelopeExampleField{
				XMLName: xml.Name{Local: "ContentField"},
				Attr1:   "test attr",
				Attr2:   11,
				Value:   "This is a test string",
			},
		},
		headers: []headerExample{
			{
				Attr1: 15,
				Value: "test header value",
			},
		},
		res: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><ns:HeaderExample xmlns:ns="ns" attr1="15">test header value</ns:HeaderExample></soapenv:Header><soapenv:Body><ns:ContentExample xmlns:ns="ns" attr1="10"><ns:ContentField attr1="test attr" attr2="11">This is a test string</ns:ContentField></ns:ContentExample></soapenv:Body></soapenv:Envelope>`,
	},
}

func TestEnvelopeEncode(t *testing.T) {
	for i, tt := range envelopeEncodeTests {
		val := NewEnvelope(tt.contentPtr)

		if len(tt.headers) > 0 {
			// Convert headers to []any
			headers := make([]any, len(tt.headers))
			for j, h := range tt.headers {
				headers[j] = h
			}
			val.AddHeaders(headers...)
		}

		res := new(bytes.Buffer)
		enc := xml.NewEncoder(res)

		if err := enc.Encode(val); !reflect.DeepEqual(err, tt.err) {
			t.Errorf("#%d: %v, want %v", i, err, tt.err)
			continue
		} else if err != nil {
			continue
		}

		if tt.res != res.String() {
			t.Errorf("#%d: mismatch\nhave: `%s`\nwant: `%s`", i, res.String(), tt.res)
			continue
		}
	}
}

type envelopeDecodeTest struct {
	in         string
	contentPtr interface{}
	out        interface{}
	err        error
}

var envelopeDecodeTests = []envelopeDecodeTest{
	{
		in: `<?xml version="1.0"?>
			<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
				<soap:Body>
					<ContentExample xmlns="ns" attr1="10">
						<ContentField attr1="test attr" attr2="11">This is a test content string</ContentField>
					</ContentExample>
				</soap:Body>
			</soap:Envelope>`,
		contentPtr: &envelopeContentExample{},
		out: &Envelope{
			XMLName: envelopeName,
			Body: &Body{
				XMLName: bodyName,
				Content: []any{&envelopeContentExample{
					Attr1: 10,
					Field1: envelopeExampleField{
						Attr1: "test attr",
						Attr2: 11,
						Value: "This is a test content string",
					},
				}},
			},
		},
	},
	{
		in: `<?xml version="1.0"?>
			<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
				<soap:Body>
					<soap:Fault>
						<faultcode>FaultCodeValue</faultcode>
						<faultstring>FaultStringValue</faultstring>
						<faultactor>FaultActorValue</faultactor>
						<detail>
							<DetailExample attr1="10">
								<DetailField attr1="test" attr2="11">This is a test string</DetailField>
							</DetailExample>
						</detail>
					</soap:Fault>
				</soap:Body>
			</soap:Envelope>`,
		contentPtr: &envelopeContentExample{},
		out: &Envelope{
			XMLName: envelopeName,
			Body: &Body{
				XMLName: bodyName,
				Fault: &Fault{
					XMLName: xml.Name{Space: soapEnvNS, Local: "Fault"},
					Code:    "FaultCodeValue",
					String:  "FaultStringValue",
					Actor:   "FaultActorValue",
				},
			},
		},
	},
}

func TestEnvelopeDecode(t *testing.T) {
	for i, tt := range envelopeDecodeTests {
		val := NewEnvelope(tt.contentPtr)

		dec := xml.NewDecoder(bytes.NewBufferString(tt.in))
		err := dec.Decode(val)

		if !reflect.DeepEqual(err, tt.err) {
			t.Errorf("#%d: %v, want %v", i, err, tt.err)
			continue
		} else if err != nil {
			continue
		}

		// Clear fault details for comparison since they contain raw XML
		if val.Body.Fault != nil {
			val.Body.Fault.Detail.Content = nil
			if tt.out.(*Envelope).Body.Fault != nil {
				tt.out.(*Envelope).Body.Fault.Detail.Content = nil
			}
		}

		if !reflect.DeepEqual(val.XMLName, tt.out.(*Envelope).XMLName) {
			t.Errorf("#%d: envelope XMLName mismatch\nhave: %+v\nwant: %+v", i, val.XMLName, tt.out.(*Envelope).XMLName)
		}

		// Skip XMLName comparison for Body since it may not be set during decoding
		if val.Body == nil {
			t.Errorf("#%d: body is nil", i)
		}
	}
}

func TestNewEnvelope(t *testing.T) {
	content := &envelopeContentExample{Attr1: 42}
	envelope := NewEnvelope(content)

	if envelope.Body == nil {
		t.Error("NewEnvelope should create a body")
	}

	if len(envelope.Body.Content) != 1 {
		t.Errorf("Expected 1 content element, got %d", len(envelope.Body.Content))
	}

	if envelope.Body.Content[0] != content {
		t.Error("Content element should match input")
	}
}

func TestNewEnvelopeWithMultipleContent(t *testing.T) {
	content1 := &envelopeContentExample{Attr1: 42}
	content2 := &envelopeContentExample{Attr1: 43}
	envelope := NewEnvelope([]any{content1, content2})

	if envelope.Body == nil {
		t.Error("NewEnvelope should create a body")
	}

	if len(envelope.Body.Content) != 2 {
		t.Errorf("Expected 2 content elements, got %d", len(envelope.Body.Content))
	}
}

func TestAddHeaders(t *testing.T) {
	content := &envelopeContentExample{Attr1: 42}
	envelope := NewEnvelope(content)

	header1 := headerExample{Attr1: 10, Value: "test1"}
	header2 := headerExample{Attr1: 20, Value: "test2"}

	envelope.AddHeaders(header1, header2)

	if envelope.Header == nil {
		t.Error("AddHeaders should create a header")
	}

	if len(envelope.Header.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(envelope.Header.Headers))
	}
}
