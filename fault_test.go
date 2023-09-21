package soap

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/m29h/xml"
)

var faultName = xml.Name{
	Space: soapEnvNS,
	Local: "Fault",
}

type faultDetailExampleField struct {
	XMLName xml.Name `xml:"DetailField"`
	Attr1   string   `xml:"attr1,attr"`
	Attr2   int32    `xml:"attr2,attr"`
	Value   string   `xml:",chardata"`
}

type faultDetailExample struct {
	XMLName xml.Name                `xml:"DetailExample"`
	Attr1   int32                   `xml:"attr1,attr"`
	Field1  faultDetailExampleField `xml:"DetailField"`
}

type faultDecodeTest struct {
	in          string
	out         interface{}
	faultErrStr string
	err         error
}

var faultDecodeTests = []faultDecodeTest{
	{
		in: `<?xml version="1.0" encoding="UTF-8"?>
		<Fault xmlns="http://schemas.xmlsoap.org/soap/envelope/">
			<faultcode>FaultCodeValue</faultcode>
			<faultstring>FaultStringValue</faultstring>
			<faultactor>FaultActorValue</faultactor>
		</Fault>`,
		out: &Fault{
			XMLName: faultName,
			Code:    "FaultCodeValue",
			String:  "FaultStringValue",
			Actor:   "FaultActorValue",
			DetailInternal: &faultDetail{
				Content: "",
			},
		},
		faultErrStr: "soap fault: FaultCodeValue (FaultStringValue)",
	},
	{
		in: `<?xml version="1.0" encoding="UTF-8"?>
		<Fault xmlns="http://schemas.xmlsoap.org/soap/envelope/">
			<faultcode>FaultCodeValue</faultcode>
			<faultstring>FaultStringValue</faultstring>
			<faultactor>FaultActorValue</faultactor>
			<detail>
				<DetailExample attr1="10">
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>
			</detail>
		</Fault>`,
		out: &Fault{
			XMLName: faultName,
			Code:    "FaultCodeValue",
			String:  "FaultStringValue",
			Actor:   "FaultActorValue",
			DetailInternal: &faultDetail{
				Content: `
				<DetailExample attr1="10">
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>
			`,
			},
		},
		faultErrStr: "soap fault: FaultCodeValue (FaultStringValue)\n" + `<DetailExample attr1="10">
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>`,
	},
	{
		in: `<?xml version="1.0" encoding="UTF-8"?>
		<Fault xmlns="http://schemas.xmlsoap.org/soap/envelope/">
			<faultcode>FaultCodeValue</faultcode>
			<faultstring>FaultStringValue</faultstring>
			<faultactor>FaultActorValue</faultactor>
			<detail>
				<DetailExample attr1="10" />
			</detail>
		</Fault>`,
		out: &Fault{
			XMLName: faultName,
			Code:    "FaultCodeValue",
			String:  "FaultStringValue",
			Actor:   "FaultActorValue",
			DetailInternal: &faultDetail{
				Content: `
				<DetailExample attr1="10" />
			`,
			},
		},
		faultErrStr: "soap fault: FaultCodeValue (FaultStringValue)\n" + `<DetailExample attr1="10" />`,
	},
	{
		in: `<?xml version="1.0" encoding="UTF-8"?>
		<Fault xmlns="http://schemas.xmlsoap.org/soap/envelope/">
			<faultcode>FaultCodeValue</faultcode>
			<faultstring>FaultStringValue</faultstring>
			<faultactor>FaultActorValue</faultactor>
			<detail>
				<DetailExample attr1="10">
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>
				<DetailExample attr1="11">
					<DetailField attr1="test2" attr2="12">This is a second test string</DetailField>
				</DetailExample>
			</detail>
		</Fault>`,
		out: &Fault{
			XMLName: faultName,
			Code:    "FaultCodeValue",
			String:  "FaultStringValue",
			Actor:   "FaultActorValue",
			DetailInternal: &faultDetail{
				Content: `
				<DetailExample attr1="10">
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>
				<DetailExample attr1="11">
					<DetailField attr1="test2" attr2="12">This is a second test string</DetailField>
				</DetailExample>
			`,
			},
		},
		faultErrStr: "soap fault: FaultCodeValue (FaultStringValue)\n" + `<DetailExample attr1="10">
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>
				<DetailExample attr1="11">
					<DetailField attr1="test2" attr2="12">This is a second test string</DetailField>
				</DetailExample>`,
	},
	{
		in: `<?xml version="1.0" encoding="UTF-8"?>
		<Fault xmlns="http://schemas.xmlsoap.org/soap/envelope/">
			<faultcode>FaultCodeValue</faultcode>
			<faultstring>FaultStringValue</faultstring>
			<faultactor>FaultActorValue</faultactor>
			<detail>
			</detail>
		</Fault>`,
		out: &Fault{
			XMLName: faultName,
			Code:    "FaultCodeValue",
			String:  "FaultStringValue",
			Actor:   "FaultActorValue",
			DetailInternal: &faultDetail{
				Content: `
			`,
			},
		},
		faultErrStr: "soap fault: FaultCodeValue (FaultStringValue)\n",
	},
	{
		in: `<?xml version="1.0" encoding="UTF-8"?>
		<Fault xmlns="http://schemas.xmlsoap.org/soap/envelope/">
			<faultcode>FaultCodeValue</faultcode>
			<faultstring>FaultStringValue</faultstring>
			<faultactor>FaultActorValue</faultactor>
			<detail>
				<DetailExample attr1="10
					<DetailField attr1="test" attr2="11">This is a test string</DetailField>
				</DetailExample>
			</detail>
		</Fault>`,
		out: &Fault{
			XMLName: faultName,
			Code:    "FaultCodeValue",
			String:  "FaultStringValue",
			Actor:   "FaultActorValue",
		},
		err: &xml.SyntaxError{Msg: "unescaped < inside quoted string", Line: 8},
	},
}

func TestFaultDecode(t *testing.T) {
	for i, tt := range faultDecodeTests {
		var val *Fault
		val = NewFault()

		dec := xml.NewDecoder(bytes.NewReader([]byte(tt.in)))

		if err := dec.Decode(val); !reflect.DeepEqual(err, tt.err) {
			t.Errorf("#%d: %v, want %v", i, err, tt.err)
			continue
		} else if err != nil {
			continue
		}
		valStr, _ := xml.Marshal(val)
		outStr, _ := xml.Marshal(tt.out)
		if string(valStr) != string(outStr) {
			//fmt.Printf("%#v\n%#v\n", val, tt.out)
			t.Errorf("#%d: mismatch\nhave: %#+v\nwant: %#+v", i, string(valStr), string(outStr))
			continue
		}
		if tt.faultErrStr != val.Error() {
			t.Errorf("#%d: mismatch\nhave %#+v\n want: %#+v", i, val.Error(), tt.faultErrStr)
		}
	}
}
