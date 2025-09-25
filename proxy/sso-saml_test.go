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

package proxy

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/c2FmZQ/tlsproxy/certmanager"
)

func TestSSOEnforceSAML(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	idpCert, err := ca.GetCert("idp.example.com")
	if err != nil {
		t.Fatalf("ca.GetCert: %v", err)
	}

	idp := newSAMLIDPServer(t, *idpCert)
	defer idp.Close()

	be := newHTTPServer(t, ctx, "https-server", ca)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			SAMLProviders: []*ConfigSAML{
				{
					Name:     "test-idp",
					SSOURL:   idp.URL,
					EntityID: "https.example.com",
					Certs:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idpCert.Certificate[0]})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idpCert.Certificate[1]})),
					ACSURL:   "https://sso.example.com/saml/acs",
					Domain:   "example.com",
				},
			},
			Backends: []*Backend{
				{
					ServerNames: []string{
						"https.example.com",
					},
					Mode: "HTTPS",
					Addresses: []string{
						be.String(),
					},
					ForwardServerName: "https-server",
					ForwardRootCAs:    []string{ca.RootCAPEM()},
					SSO: &BackendSSO{
						Provider: "test-idp",
					},
				},
				{
					ServerNames: []string{
						"sso.example.com",
					},
					Mode: "HTTPS",
					SSO: &BackendSSO{
						Provider: "test-idp",
					},
				},
			},
		},
		ca,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}

	get := func(urlToGet string, hdr http.Header, postBody []byte) (int, string, string) {
		if postBody == nil {
			t.Logf("GET(%q)", urlToGet)
		} else {
			t.Logf("POST(%q)", urlToGet)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			RootCAs: ca.RootCACertPool(),
		}
		var host string
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host = addr
			var d net.Dialer
			if strings.Contains(addr, "example.com") {
				return d.DialContext(ctx, "tcp", proxy.listener.Addr().String())
			}
			return d.DialContext(ctx, network, addr)
		}
		client := http.Client{
			Transport: transport,
			Jar:       jar,
		}
		req, err := http.NewRequest("GET", urlToGet, nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		if postBody != nil {
			req.Method = "POST"
			req.Body = io.NopCloser(bytes.NewReader(postBody))
		}
		if hdr != nil {
			req.Header = hdr
		}
		if req.Method == "POST" {
			for _, c := range jar.Cookies(req.URL) {
				req.AddCookie(c)
				if c.Name == "__tlsproxySid" {
					t.Logf("%s = %q", c.Name, c.Value)
					req.Header.Set("x-csrf-token", c.Value)
					break
				}
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: get failed: %v", urlToGet, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: body read: %v", urlToGet, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("%s: body close: %v", urlToGet, err)
		}
		return resp.StatusCode, string(body), host
	}

	code, body, _ := get("https://https.example.com/blah", http.Header{"x-skip-login-confirmation": []string{"yes"}}, nil)
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	m := regexp.MustCompile(`<form method="POST" action="([^"]*)"><input type="hidden" name="([^"]*)" value="([^"]*)"`).FindStringSubmatch(body)
	if len(m) != 4 {
		t.Fatalf("FindStringSubmatch: %v", m)
	}
	action := m[1]
	name := m[2]
	value := strings.ReplaceAll((m[3]), "&#43;", "+")

	hdrs := http.Header{}
	hdrs.Set("content-type", "application/x-www-form-urlencoded")
	data := url.Values{}
	data.Set(name, value)

	code, body, _ = get(action, hdrs, []byte(data.Encode()))
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	if got, want := body, "[https-server] /blah\n"; got != want {
		t.Errorf("Body = %v, want %v", got, want)
	}
	if idp.count == 0 {
		t.Error("IDP Server never called")
	}
}

func newSAMLIDPServer(t *testing.T, cert tls.Certificate) *samlIDPServer {
	idp := &samlIDPServer{
		t: t,
		samlServer: &samlTestServer{
			cert: cert,
		},
	}
	mux := http.NewServeMux()
	log := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			t.Logf("[IDP SERVER] %s %s", req.Method, req.RequestURI)
			req.ParseForm()
			for k, v := range req.Form {
				t.Logf("[IDP SERVER]  %s: %v", k, v)
			}
			next.ServeHTTP(w, req)

			idp.mu.Lock()
			defer idp.mu.Unlock()
			idp.count++
		})
	}
	mux.Handle("/", log(idp.samlServer))
	idp.Server = httptest.NewServer(mux)
	return idp
}

type samlIDPServer struct {
	*httptest.Server
	t          *testing.T
	samlServer *samlTestServer

	mu    sync.Mutex
	count int
}

const (
	samlResponseTemplate = `<html>
	<body onload="document.forms[0].submit()">
	<form method="POST" action="{{.URL}}"><input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"/>
	</form>
	</body>
	</html>`
)

// samlTestServer is a SAML Identity Provider for testing.
type samlTestServer struct {
	cert tls.Certificate
}

func (s *samlTestServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	var reqData samlAuthnRequest
	if err := xml.Unmarshal(xmlBytes, &reqData); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	issuer := reqData.Issuer.Value
	resp := samlResponse{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:           rand.Text(),
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
func (s *samlTestServer) newAssertion(now time.Time, reqData samlAuthnRequest) (string, error) {
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
		ID:           rand.Text(),
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

func (s *samlTestServer) sign(data []byte) ([]byte, error) {
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

type samlAuthnRequest struct {
	XMLName                     xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string     `xml:",attr"`
	Version                     string     `xml:",attr"`
	IssueInstant                string     `xml:",attr"`
	Destination                 string     `xml:",attr"`
	ProtocolBinding             string     `xml:",attr"`
	AssertionConsumerServiceURL string     `xml:",attr"`
	Issuer                      samlIssuer `xml:"Issuer"`
}

type samlIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}
