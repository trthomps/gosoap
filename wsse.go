package soap

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Implements the WS-Security standard using X.509 certificate signatures.
// https://www.di-mgt.com.au/xmldsig2.html is a handy reference to the WS-Security signing process.

const (
	wsseNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	wsuNS  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	dsigNS = "http://www.w3.org/2000/09/xmldsig#"

	encTypeBinary    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	valTypeX509Token = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"

	canonicalizationExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
	rsaSha1Sig                    = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sha1Sig                       = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// WSSEAuthInfo contains the information required to use WS-Security X.509 signing.
type WSSEAuthInfo struct {
	certDER tls.Certificate
	key     crypto.PrivateKey
	sigRef  []signatureReference
}

// NewWSSEAuthInfo retrieves the supplied certificate path and key path for signing SOAP requests.
// These requests will be secured using the WS-Security X.509 security standard.
func NewWSSEAuthInfo(certPath string, keyPath string) (*WSSEAuthInfo, error) {

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &WSSEAuthInfo{
		certDER: cert,
		key:     cert.PrivateKey,
		sigRef:  make([]signatureReference, 0),
	}, nil
}

type binarySecurityToken struct {
	XMLName xml.Name `xml:"wsse:BinarySecurityToken"`
	XMLNS   string   `xml:"xmlns:wsu,attr"`

	WsuID string `xml:"wsu:Id,attr"`

	EncodingType string `xml:"EncodingType,attr"`
	ValueType    string `xml:"ValueType,attr"`

	Value string `xml:",chardata"`
}

type canonicalizationMethod struct {
	XMLName   xml.Name `xml:"CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type signatureMethod struct {
	XMLName   xml.Name `xml:"SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type digestMethod struct {
	XMLName   xml.Name `xml:"DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type digestValue struct {
	XMLName xml.Name `xml:"DigestValue"`
	Value   string   `xml:",chardata"`
}

type transform struct {
	XMLName   xml.Name `xml:"Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

type transforms struct {
	XMLName   xml.Name `xml:"Transforms"`
	Transform transform
}

type signatureReference struct {
	XMLName xml.Name `xml:"Reference"`
	URI     string   `xml:"URI,attr"`

	Transforms transforms

	DigestMethod digestMethod
	DigestValue  digestValue
}

type signedInfo struct {
	XMLName xml.Name `xml:"SignedInfo"`
	XMLNS   string   `xml:"xmlns,attr"`

	CanonicalizationMethod canonicalizationMethod
	SignatureMethod        signatureMethod
	Reference              []signatureReference
}

// =============================================================================
// Web Services Security Utility (WSU)
// =============================================================================
// timestamp allows Timestamps to be applied anywhere element wildcards are
// present, including as a SOAP header.
type timestamp struct {
	XMLName xml.Name `xml:"wsu:Timestamp,omitempty"`
	XMLNS   string   `xml:"xmlns:wsu,attr"`
	WsuID   string   `xml:"wsu:Id,attr"`
	Created string   `xml:"wsu:Created"`
	Expires string   `xml:"wsu:Expires"`
}

type strReference struct {
	XMLName   xml.Name `xml:"wsse:Reference"`
	ValueType string   `xml:"ValueType,attr"`
	URI       string   `xml:"URI,attr"`
}

type securityTokenReference struct {
	XMLName xml.Name `xml:"wsse:SecurityTokenReference"`
	XMLNS   string   `xml:"xmlns:wsu,attr"`

	Reference strReference
}

type keyInfo struct {
	XMLName xml.Name `xml:"KeyInfo"`

	SecurityTokenReference securityTokenReference
}

type signature struct {
	XMLName xml.Name `xml:"Signature"`
	XMLNS   string   `xml:"xmlns,attr"`

	SignedInfo     signedInfo
	SignatureValue string `xml:"SignatureValue"`
	KeyInfo        keyInfo
}

type security struct {
	XMLName        xml.Name `xml:"wsse:Security"`
	XMLNS          string   `xml:"xmlns:wsse,attr"`
	MustUnderstand int      `xml:"mustUnderstand,attr"`

	BinarySecurityToken binarySecurityToken
	Signature           signature
	Timestamp           timestamp
}

func getWsuID() string {
	return "WSSE" + uuid.New().String()
}
func (w *WSSEAuthInfo) addSignature(body any) error {
	// 0. We create the id value and assign it to the incoming body.WsuID via reflect
	id := getWsuID()
	val := reflect.ValueOf(body)

	if val.Kind().String() != "ptr" {
		return errors.New("addSignature: body must be pointer")
	}

	if val.Elem().Kind().String() != "struct" {
		return errors.New("addSignature: body must point to struct")
	}

	found := false
	for i := 0; i < val.Elem().NumField(); i++ {
		if strings.ToLower(val.Elem().Type().Field(i).Name) == "wsuid" {
			val.Elem().Field(i).SetString(id)
			found = true
		}
	}
	if !found {
		return errors.New("addSignature: body did not contain a WsuID struct field")
	}

	// 1. We create the DigestValue of the body.

	// We make some changes to canonicalize things.
	// Since we have a copy, this is ok
	bodyEnc, err := xml.Marshal(body)
	if err != nil {
		return err
	}

	canonBodyEnc, err := canonicalize(bodyEnc, "")
	if err != nil {
		return err
	}

	bodyHasher := sha1.New()
	bodyHasher.Write(canonBodyEnc)
	encodedBodyDigest := base64.StdEncoding.EncodeToString(bodyHasher.Sum(nil))
	w.sigRef = append(w.sigRef, signatureReference{
		URI: "#" + id,
		Transforms: transforms{
			Transform: transform{
				Algorithm: canonicalizationExclusiveC14N,
			},
		},
		DigestMethod: digestMethod{
			Algorithm: sha1Sig,
		},
		DigestValue: digestValue{
			Value: encodedBodyDigest,
		},
	})
	return nil
}

func (w *WSSEAuthInfo) securityHeader(body any) (security, error) {

	if err := w.addSignature(body); err != nil {
		return security{}, err
	}
	timestamp := timestamp{
		XMLNS:   wsuNS,
		WsuID:   "",
		Created: time.Now().UTC().Format("2006-01-02T15:04:05.999Z07:00"),
		Expires: time.Now().UTC().Add(10 * time.Second).Format("2006-01-02T15:04:05.999Z07:00"),
	}

	if err := w.addSignature(&timestamp); err != nil {
		return security{}, err
	}
	// 2. Set the DigestValue then sign the 'SignedInfo' struct
	signedInfo := signedInfo{
		XMLNS: dsigNS,
		CanonicalizationMethod: canonicalizationMethod{
			Algorithm: canonicalizationExclusiveC14N,
		},
		SignatureMethod: signatureMethod{
			Algorithm: rsaSha1Sig,
		},
		Reference: w.sigRef,
	}

	signedInfoEnc, err := xml.Marshal(signedInfo)
	if err != nil {
		return security{}, err
	}

	signedInfoHasher := sha1.New()
	signedInfoHasher.Write(signedInfoEnc)
	signedInfoDigest := signedInfoHasher.Sum(nil)

	privateKey := w.key.(*rsa.PrivateKey)

	signatureValue, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, signedInfoDigest)
	if err != nil {
		return security{}, err
	}

	encodedSignatureValue := base64.StdEncoding.EncodeToString(signatureValue)
	encodedCertificateValue := base64.StdEncoding.EncodeToString(w.certDER.Certificate[0])
	securityTokenID := getWsuID()
	secHeader := security{
		XMLNS:          wsseNS,
		MustUnderstand: 1,
		BinarySecurityToken: binarySecurityToken{
			XMLNS:        wsuNS,
			WsuID:        securityTokenID,
			EncodingType: encTypeBinary,
			ValueType:    valTypeX509Token,
			Value:        encodedCertificateValue,
		},
		Signature: signature{
			XMLNS:          dsigNS,
			SignedInfo:     signedInfo,
			SignatureValue: encodedSignatureValue,
			KeyInfo: keyInfo{
				SecurityTokenReference: securityTokenReference{
					XMLNS: wsuNS,
					Reference: strReference{
						ValueType: valTypeX509Token,
						URI:       "#" + securityTokenID,
					},
				},
			},
		},
		Timestamp: timestamp,
	}
	w.sigRef = make([]signatureReference, 0)
	return secHeader, nil
}
