// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	samlResponseTemplate = `<html>
	<body onload="document.forms[0].submit()">
	<form method="POST" action="{{.URL}}"><input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"/>
	</form>
	</body>
	</html>`
)

// NewServer returns a new SAML IdP server for testing.
func NewServer(cert tls.Certificate) *ProviderServer {
	return &ProviderServer{
		cert: cert,
	}
}

// ProviderServer is a SAML Identity Provider for testing.
type ProviderServer struct {
	cert tls.Certificate
}

func (s *ProviderServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, err := base64.StdEncoding.DecodeString(req.FormValue("SAMLRequest"))
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(b)))
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var reqData SAMLAuthnRequest
	if err := xml.Unmarshal(xmlBytes, &reqData); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	issuer := reqData.Issuer.Value
	resp := samlResponse{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:           "id-" + fmt.Sprintf("%x", time.Now().UnixNano()),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339Nano),
		Destination:  reqData.AssertionConsumerServiceURL,
		InResponseTo: reqData.ID,
		Issuer: samlIssuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Status: samlStatus{
			StatusCode: samlStatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	assertion, err := s.newAssertion(now, reqData)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := resp.AddAssertion(assertion); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	buf, err := xml.MarshalIndent(resp, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.New("saml-response").Parse(samlResponseTemplate))
	data := struct {
		URL          string
		SAMLResponse string
	}{
		URL:          reqData.AssertionConsumerServiceURL,
		SAMLResponse: string(base64.StdEncoding.EncodeToString(buf)),
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}
func (s *ProviderServer) newAssertion(now time.Time, reqData SAMLAuthnRequest) (string, error) {
	issuer := reqData.Issuer.Value
	acsURL, err := url.Parse(reqData.AssertionConsumerServiceURL)
	if err != nil {
		return "", err
	}
	host := acsURL.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	assertion := samlAssertion{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:           "id-" + fmt.Sprintf("%x", time.Now().UnixNano()),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339Nano),
		Issuer: samlIssuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Subject: samlSubject{
			NameID: samlNameID{
				Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Value:  "test@example.com",
			},
			SubjectConfirmation: samlSubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: samlSubjectConfirmationData{
					InResponseTo: reqData.ID,
					NotOnOrAfter: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
					Recipient:    reqData.AssertionConsumerServiceURL,
				},
			},
		},
		Conditions: samlConditions{
			NotBefore:    now.Format(time.RFC3339Nano),
			NotOnOrAfter: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
			AudienceRestriction: samlAudienceRestriction{
				Audience: []string{"https://" + host + "/"},
			},
		},
		AttributeStatement: samlAttributeStatement{
			Attributes: []samlAttribute{
				{
					Name: "email",
					AttributeValue: []string{
						"test@example.com",
					},
				},
				{
					Name: "name",
					AttributeValue: []string{
						"Test User",
					},
				},
			},
		},
	}
	buf, err := xml.Marshal(assertion)
	if err != nil {
		return "", err
	}
	signed, err := s.sign(buf)
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

type memoryKeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *memoryKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func (s *ProviderServer) sign(data []byte) ([]byte, error) {
	ks := &memoryKeyStore{
		s.cert.PrivateKey.(*rsa.PrivateKey),
		s.cert.Certificate[0],
	}
	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod)

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, err
	}
	doc.Indent(2)
	root := doc.Root()
	signed, err := ctx.SignEnveloped(root)
	if err != nil {
		return nil, err
	}
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signed)
	return signedDoc.WriteToBytes()
}

type samlResponse struct {
	XMLName      xml.Name `xml:"samlp:Response"`
	XMLNS        string   `xml:"xmlns:samlp,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`

	Issuer       samlIssuer
	Status       samlStatus `xml:"Status"`
	RawAssertion string     `xml:",innerxml"`
}

func (r *samlResponse) AddAssertion(a string) error {
	r.RawAssertion = a
	return nil
}

type samlStatus struct {
	XMLName    xml.Name       `xml:"Status"`
	StatusCode samlStatusCode `xml:"StatusCode"`
}

type samlStatusCode struct {
	XMLName xml.Name `xml:"StatusCode"`
	Value   string   `xml:"Value,attr"`
}

type samlAssertion struct {
	XMLName      xml.Name `xml:"saml:Assertion"`
	XMLNS        string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`

	Issuer             samlIssuer
	Subject            samlSubject
	Conditions         samlConditions
	AttributeStatement samlAttributeStatement
}

type samlSubject struct {
	XMLName             xml.Name `xml:"saml:Subject"`
	NameID              samlNameID
	SubjectConfirmation samlSubjectConfirmation
}

type samlNameID struct {
	XMLName xml.Name `xml:"saml:NameID"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

type samlSubjectConfirmation struct {
	XMLName xml.Name `xml:"saml:SubjectConfirmation"`

	Method                  string `xml:",attr"`
	SubjectConfirmationData samlSubjectConfirmationData
}

type samlSubjectConfirmationData struct {
	XMLName      xml.Name `xml:"saml:SubjectConfirmationData"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
}

type samlConditions struct {
	XMLName             xml.Name `xml:"saml:Conditions"`
	NotBefore           string   `xml:",attr"`
	NotOnOrAfter        string   `xml:",attr"`
	AudienceRestriction samlAudienceRestriction
}

type samlAudienceRestriction struct {
	XMLName  xml.Name `xml:"saml:AudienceRestriction"`
	Audience []string `xml:"saml:Audience"`
}

type samlAttributeStatement struct {
	XMLName    xml.Name        `xml:"saml:AttributeStatement"`
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	XMLName        xml.Name `xml:"saml:Attribute"`
	Name           string   `xml:"Name,attr"`
	AttributeValue []string `xml:"AttributeValue"`
}
