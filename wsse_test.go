package soap

import (
	"encoding/xml"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type newWsseAuthInfoTest struct {
	name       string
	inCertPath string
	inKeyPath  string
	err        error
}

var newWsseAuthInfoTests = []newWsseAuthInfoTest{
	{
		name:       "base case",
		inCertPath: "./testdata/cert.pem",
		inKeyPath:  "./testdata/key.pem",
		err:        nil,
	},
	{
		name:       "invalid key file case",
		inCertPath: "./testdata/cert.pem",
		inKeyPath:  "./testdata/badkey.pem",
		err:        errors.New("tls: private key does not match public key"),
	},
}

func TestNewWSSEAuthInfo(t *testing.T) {
	for _, tt := range newWsseAuthInfoTests {
		t.Run(tt.name, func(t *testing.T) {
			wsseInfo, err := NewWSSEAuthInfo(tt.inCertPath, tt.inKeyPath)
			assert.Equal(t, tt.err, err)
			if tt.err == nil {
				assert.NotNil(t, wsseInfo)
			}
		})
	}
}

func TestAddSignature(t *testing.T) {
	wsseInfo, err := NewWSSEAuthInfo(newWsseAuthInfoTests[0].inCertPath, newWsseAuthInfoTests[0].inKeyPath)
	assert.NoError(t, err)
	body := &timestamp{
		WsuID:   "",
		Created: "_",
		Expires: "_",
	}
	err = wsseInfo.addSignature(body)
	assert.NoError(t, err)
	//there must be
	assert.NotEqual(t, len(body.WsuID), 0)
	assert.Equal(t, len(wsseInfo.sigRef), 1)
}

func TestSecurityHeader(t *testing.T) {
	wsseInfo, err := NewWSSEAuthInfo(newWsseAuthInfoTests[0].inCertPath, newWsseAuthInfoTests[0].inKeyPath)
	assert.NoError(t, err)
	body := &timestamp{
		WsuID: "",
	}
	secHeader, err := wsseInfo.securityHeader(body)
	assert.NoError(t, err)
	//there must be the WsuID set to a string of a length larger than 0 for body and timestamp
	assert.NotEqual(t, len(body.WsuID), 0)
	assert.NotEqual(t, len(secHeader.Timestamp.WsuID), 0)
	//timestamp must be autoset to some value
	assert.NotEqual(t, len(secHeader.Timestamp.Created), 0)
	assert.NotEqual(t, len(secHeader.Timestamp.Expires), 0)
	//the sigRef must be cleared after generating the header
	assert.Equal(t, len(wsseInfo.sigRef), 0)
	//the length of signed references in the header must be 2 (body+timestamp)
	assert.Len(t, secHeader.Signature.SignedInfo.Reference, 2)
	assert.Equal(t, secHeader.MustUnderstand, 1)
	bodyEnc, err := xml.MarshalIndent(&secHeader, "", "  ")
	b := string(bodyEnc)
	assert.NoError(t, err)
	//fmt.Println(b)
	assert.Contains(t, b, "</wsu:Expires>")

}
