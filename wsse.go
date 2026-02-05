package soap

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/m29h/xml"
)

// Implements the WS-Security standard using X.509 certificate signatures.
// use SHA256 as default HMAC for signing purposes
// https://www.di-mgt.com.au/xmldsig2.html is a handy reference to the WS-Security signing process.

const (
	encTypeBinary                 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	valTypeX509Token              = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	canonicalizationExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

var (
	// ErrUnableToSignEmptyEnvelope is returned if the envelope to be signed is empty. This is not valid.
	ErrUnableToSignEmptyEnvelope = errors.New("unable to sign, envelope is empty")

	digestMap = map[crypto.Hash]string{
		crypto.SHA1:   "http://www.w3.org/2000/09/xmldsig#sha1",
		crypto.SHA224: "http://www.w3.org/2001/04/xmldsig-more#sha224",
		crypto.SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
		crypto.SHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
		crypto.SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
	}

	sigMap = map[x509.SignatureAlgorithm]string{
		x509.SHA1WithRSA:     "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		x509.SHA256WithRSA:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		x509.SHA384WithRSA:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
		x509.SHA512WithRSA:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
		x509.ECDSAWithSHA1:   "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
		x509.ECDSAWithSHA256: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		x509.ECDSAWithSHA384: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
		x509.ECDSAWithSHA512: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
	}
)

func x509SignatureAlgorithmFromString(algo string) (x509.SignatureAlgorithm, error) {
	switch strings.ToLower(algo) {
	case "rsa-sha1":
		return x509.SHA1WithRSA, nil
	case "rsa-sha256":
		return x509.SHA256WithRSA, nil
	case "rsa-sha384":
		return x509.SHA384WithRSA, nil
	case "rsa-sha512":
		return x509.SHA512WithRSA, nil
	case "ecdsa-sha1":
		return x509.ECDSAWithSHA1, nil
	case "ecdsa-sha256":
		return x509.ECDSAWithSHA256, nil
	case "ecdsa-sha384":
		return x509.ECDSAWithSHA384, nil
	case "ecdsa-sha512":
		return x509.ECDSAWithSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported signature algorithm %s", algo)
	}
}

func cryptoHashFromX509SignatureAlgorithm(a x509.SignatureAlgorithm) crypto.Hash {
	switch a {
	case x509.ECDSAWithSHA1, x509.SHA1WithRSA:
		return crypto.SHA1
	case x509.ECDSAWithSHA256, x509.SHA256WithRSA:
		return crypto.SHA256
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA:
		return crypto.SHA384
	case x509.ECDSAWithSHA512, x509.SHA512WithRSA:
		return crypto.SHA512
	default:
		return 0
	}
}

func cryptoHashFromString(algo string) (crypto.Hash, error) {
	switch strings.ToLower(algo) {
	case "sha1":
		return crypto.SHA1, nil
	case "sha224":
		return crypto.SHA224, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm %s", algo)
	}
}

func newHasherFromCryptoHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New()
	case crypto.SHA224:
		return sha256.New224()
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return nil
	}
}

// WSSEAuthInfo contains the information required to use WS-Security X.509 signing.
type WSSEAuthInfo struct {
	certDER tls.Certificate
	key     crypto.PrivateKey
	sigRef  []signatureReference

	signatureAlgorithm x509.SignatureAlgorithm
	signatureMethod    crypto.Hash
	signatureURI       string

	digestMethod crypto.Hash
	digestURI    string
}

type WSSEAuthInfoOption interface {
	apply(*WSSEAuthInfo) error
}

type funcWSSEAuthInfoOption struct {
	f func(*WSSEAuthInfo) error
}

func (f *funcWSSEAuthInfoOption) apply(w *WSSEAuthInfo) error {
	return f.f(w)
}

func newFuncWSSEAuthInfoOption(f func(*WSSEAuthInfo) error) *funcWSSEAuthInfoOption {
	return &funcWSSEAuthInfoOption{f: f}
}

// WithWSSEAuthInfoCertPath creates a WSSEAuthInfoOption that sets the certificate and key from the given file paths.
func WithWSSEAuthInfoCertPath(certPath string, keyPath string) WSSEAuthInfoOption {
	return newFuncWSSEAuthInfoOption(func(w *WSSEAuthInfo) error {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return err
		}
		w.certDER = cert
		w.key = cert.PrivateKey
		return nil
	})
}

// WithWSSEAuthInfoCert creates a WSSEAuthInfoOption that sets the certificate and key from a tls.Certificate.
func WithWSSEAuthInfoCert(cert tls.Certificate) WSSEAuthInfoOption {
	return newFuncWSSEAuthInfoOption(func(w *WSSEAuthInfo) error {
		w.certDER = cert
		w.key = cert.PrivateKey
		return nil
	})
}

func WithWSSEAuthInfoSignatureAlgorithm(algo x509.SignatureAlgorithm) WSSEAuthInfoOption {
	return newFuncWSSEAuthInfoOption(func(w *WSSEAuthInfo) error {
		w.signatureAlgorithm = algo
		return nil
	})
}

func WithWSSEAuthInfoSignatureAlgorithmString(algo string) WSSEAuthInfoOption {
	return newFuncWSSEAuthInfoOption(func(w *WSSEAuthInfo) error {
		a, err := x509SignatureAlgorithmFromString(algo)
		if err != nil {
			return err
		}
		w.signatureAlgorithm = a
		return nil
	})
}

func WithWSSEAuthInfoDigestMethod(method crypto.Hash) WSSEAuthInfoOption {
	return newFuncWSSEAuthInfoOption(func(w *WSSEAuthInfo) error {
		w.digestMethod = method
		return nil
	})
}

func WithWSSEAuthInfoDigestMethodString(method string) WSSEAuthInfoOption {
	return newFuncWSSEAuthInfoOption(func(w *WSSEAuthInfo) error {
		m, err := cryptoHashFromString(method)
		if err != nil {
			return err
		}
		w.digestMethod = m
		return nil
	})
}

// NewWSSEAuthInfo retrieves the supplied certificate path and key path for signing SOAP requests.
// These requests will be secured using the WS-Security X.509 security standard.
func NewWSSEAuthInfo(options ...WSSEAuthInfoOption) (*WSSEAuthInfo, error) {
	authInfo := &WSSEAuthInfo{
		sigRef:             make([]signatureReference, 0),
		signatureAlgorithm: x509.SHA256WithRSA,
		digestMethod:       crypto.SHA256,
	}
	for _, opt := range options {
		if err := opt.apply(authInfo); err != nil {
			return nil, err
		}
	}
	if authInfo.certDER.PrivateKey == nil {
		return nil, errors.New("WSSEAuthInfo: private key is nil, ensure you have set the certificate and key")
	}
	if len(authInfo.certDER.Certificate) == 0 {
		return nil, errors.New("WSSEAuthInfo: certificate is nil or empty, ensure you have set the certificate and key")
	}
	if _, ok := authInfo.key.(*rsa.PrivateKey); !ok {
		return nil, errors.New("WSSEAuthInfo: private key is not of type *rsa.PrivateKey, ensure you have set the certificate and key")
	}

	var ok bool

	authInfo.signatureURI, ok = sigMap[authInfo.signatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("WSSEAuthInfo: signature algorithm %s is not supported", authInfo.signatureAlgorithm)
	}
	authInfo.signatureMethod = cryptoHashFromX509SignatureAlgorithm(authInfo.signatureAlgorithm)

	authInfo.digestURI, ok = digestMap[authInfo.digestMethod]
	if !ok {
		return nil, fmt.Errorf("WSSEAuthInfo: digest method %s is not supported", authInfo.digestMethod)
	}

	return authInfo, nil
}

type binarySecurityToken struct {
	XMLName      xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd BinarySecurityToken"`
	WsuID        string   `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr"`
	EncodingType string   `xml:"EncodingType,attr"`
	ValueType    string   `xml:"ValueType,attr"`
	Value        string   `xml:",chardata"`
}

type inclusiveNamespaces struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2001/10/xml-exc-c14n# InclusiveNamespaces"`
	PrefixList string   `xml:"PrefixList,attr"`
}

type canonicalizationMethod struct {
	XMLName             xml.Name `xml:"CanonicalizationMethod"`
	Algorithm           string   `xml:"Algorithm,attr"`
	InclusiveNamespaces inclusiveNamespaces
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
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI     string   `xml:"URI,attr"`

	Transforms transforms

	DigestMethod digestMethod
	DigestValue  digestValue
}

type signedInfo struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`

	CanonicalizationMethod canonicalizationMethod
	SignatureMethod        signatureMethod
	Reference              []signatureReference
}

const RFC3339milli = "2006-01-02T15:04:05.999Z07:00"

type soapTime time.Time

func (t soapTime) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(time.Time(t).Format(RFC3339milli), start)
}

func (t *soapTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	t2, err := time.Parse(RFC3339milli, s)
	if err != nil {
		return err
	}
	*t = soapTime(t2)
	return nil
}

func (t soapTime) String() string {
	return time.Time(t).Format(RFC3339milli)
}

func soapTimeNow() soapTime {
	return soapTime(time.Now())
}

func soapTimeFromTime(t time.Time) soapTime {
	return soapTime(t)
}

// =============================================================================
// Web Services Security Utility (WSU)
// =============================================================================
// timestamp allows Timestamps to be applied anywhere element wildcards are
// present, including as a SOAP header.
type timestamp struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Timestamp,omitempty"`
	WsuID   string   `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr"`
	Created soapTime `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Created"`
	Expires soapTime `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Expires"`
}

type strReference struct {
	XMLName   xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Reference"`
	ValueType string   `xml:"ValueType,attr"`
	URI       string   `xml:"URI,attr"`
}

type securityTokenReference struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd SecurityTokenReference"`

	Reference strReference
}

type keyInfo struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`

	SecurityTokenReference securityTokenReference
}

type signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

	SignedInfo     signedInfo
	SignatureValue string `xml:"SignatureValue"`
	KeyInfo        keyInfo
}

type security struct {
	XMLName        xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`
	MustUnderstand int      `xml:"http://schemas.xmlsoap.org/soap/envelope/ mustUnderstand,attr"`

	BinarySecurityToken binarySecurityToken
	Signature           signature
	Timestamp           timestamp
}

func getWsuID() string {
	return "WSSE" + uuid.New().String()
}

// canonicalize normalizes XML serialization for C14N-compatible digest computation.
// It parses the XML through etree and re-serializes with canonical text and attribute
// settings, which decodes character references (e.g., &#xA; -> 0x0A), uses canonical
// end tags, and normalizes attribute values.
//
// Note: this does not implement full Exclusive C14N (namespace axis sorting, superfluous
// namespace exclusion). It is sufficient for canonicalizing xml.Marshal output where
// namespace declarations are already minimal and consistently ordered.
func canonicalize(xmlBytes []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("canonicalize: failed to parse XML: %w", err)
	}
	doc.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
	var buf bytes.Buffer
	if _, err := doc.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("canonicalize: failed to write XML: %w", err)
	}
	return buf.Bytes(), nil
}

func (w *WSSEAuthInfo) addSignature(element any) error {
	// 0. We create the id value and assign it to the incoming body.WsuID via reflect
	id := getWsuID()
	val := reflect.ValueOf(element)

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

	// 1. We create the DigestValue of the body using Exclusive C14N canonicalization.
	bodyEnc, err := xml.Marshal(element)
	if err != nil {
		return err
	}

	bodyCanonical, err := canonicalize(bodyEnc)
	if err != nil {
		return err
	}

	bodyHasher := newHasherFromCryptoHash(w.digestMethod)
	bodyHasher.Write(bodyCanonical)
	w.sigRef = append(w.sigRef, signatureReference{
		URI: "#" + id,
		Transforms: transforms{
			Transform: transform{
				Algorithm: canonicalizationExclusiveC14N,
			},
		},
		DigestMethod: digestMethod{
			Algorithm: w.digestURI,
		},
		DigestValue: digestValue{
			Value: base64.StdEncoding.EncodeToString(bodyHasher.Sum(nil)),
		},
	})
	return nil
}
func (w *WSSEAuthInfo) Header() HeaderBuilder {
	return func(body any) (any, error) {
		return w.securityHeader(body)
	}
}

func (w *WSSEAuthInfo) securityHeader(body any) (security, error) {
	if body == nil {
		return security{}, ErrUnableToSignEmptyEnvelope
	}

	if err := w.addSignature(body); err != nil {
		return security{}, err
	}
	now := time.Now().UTC()
	ts := timestamp{
		WsuID:   "",
		Created: soapTimeFromTime(now),
		Expires: soapTimeFromTime(now.Add(10 * time.Second)),
	}

	if err := w.addSignature(&ts); err != nil {
		return security{}, err
	}
	// 2. Set the DigestValue then sign the 'SignedInfo' struct
	si := signedInfo{
		CanonicalizationMethod: canonicalizationMethod{
			Algorithm: canonicalizationExclusiveC14N,
		},
		SignatureMethod: signatureMethod{
			Algorithm: w.signatureURI,
		},
		Reference: w.sigRef,
	}

	signedInfoEnc, err := xml.Marshal(si)
	if err != nil {
		return security{}, err
	}

	signedInfoCanonical, err := canonicalize(signedInfoEnc)
	if err != nil {
		return security{}, err
	}

	signedInfoHasher := newHasherFromCryptoHash(w.signatureMethod)
	signedInfoHasher.Write(signedInfoCanonical)
	signedInfoDigest := signedInfoHasher.Sum(nil)

	var signatureValue []byte
	switch w.key.(type) {
	case *rsa.PrivateKey:
		signatureValue, err = rsa.SignPKCS1v15(rand.Reader, w.key.(*rsa.PrivateKey), w.signatureMethod, signedInfoDigest)
	case *ecdsa.PrivateKey:
		signatureValue, err = ecdsa.SignASN1(rand.Reader, w.key.(*ecdsa.PrivateKey), signedInfoDigest)
	default:
		return security{}, errors.New("WSSEAuthInfo: private key is not of type *rsa.PrivateKey or *ecdsa.PrivateKey")
	}
	if err != nil {
		return security{}, err
	}

	encodedSignatureValue := base64.StdEncoding.EncodeToString(signatureValue)
	encodedCertificateValue := base64.StdEncoding.EncodeToString(w.certDER.Certificate[0])
	securityTokenID := getWsuID()
	secHeader := security{
		MustUnderstand: 1,
		BinarySecurityToken: binarySecurityToken{
			WsuID:        securityTokenID,
			EncodingType: encTypeBinary,
			ValueType:    valTypeX509Token,
			Value:        encodedCertificateValue,
		},
		Signature: signature{
			SignedInfo:     si,
			SignatureValue: encodedSignatureValue,
			KeyInfo: keyInfo{
				SecurityTokenReference: securityTokenReference{
					Reference: strReference{
						ValueType: valTypeX509Token,
						URI:       "#" + securityTokenID,
					},
				},
			},
		},
		Timestamp: ts,
	}
	w.sigRef = make([]signatureReference, 0)
	return secHeader, nil
}
