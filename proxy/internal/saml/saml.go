// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@rthellend.com>
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
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

type CookieManager interface {
	SetAuthTokenCookie(w http.ResponseWriter, userID, sessionID string) error
	ClearCookies(w http.ResponseWriter) error
}

type EventRecorder interface {
	Record(string)
}

type Config struct {
	SSOURL   string
	EntityID string
	Certs    string
	ACSURL   string
}

type Provider struct {
	cfg     Config
	er      EventRecorder
	cm      CookieManager
	dsigCtx *dsig.ValidationContext

	mu     sync.Mutex
	states map[string]*samlState
}

type samlState struct {
	Created     time.Time
	OriginalURL string
}

func New(cfg Config, er EventRecorder, cm CookieManager) (*Provider, error) {
	certs, err := readCerts(cfg.Certs)
	if err != nil {
		return nil, err
	}
	dsigCtx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: certs,
	})
	p := &Provider{
		cfg:     cfg,
		er:      er,
		cm:      cm,
		dsigCtx: dsigCtx,
		states:  make(map[string]*samlState),
	}
	if _, err := url.Parse(cfg.SSOURL); err != nil {
		return nil, fmt.Errorf("SSOURL: %v", err)
	}
	if _, err := url.Parse(cfg.ACSURL); err != nil {
		return nil, fmt.Errorf("ACSURL: %v", err)
	}
	return p, nil
}

func (p *Provider) RequestLogin(w http.ResponseWriter, req *http.Request, origURL string) {
	var id [12]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idStr := hex.EncodeToString(id[:])
	p.mu.Lock()
	p.states[idStr] = &samlState{
		Created:     time.Now(),
		OriginalURL: origURL,
	}
	p.mu.Unlock()

	authReq := &samlAuthnRequest{
		XMLName:                     xml.Name{Local: "samlp:samlAuthnRequest"},
		ID:                          idStr,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format(time.RFC3339Nano),
		Destination:                 p.cfg.SSOURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		AssertionConsumerServiceURL: p.cfg.ACSURL,
		Issuer: samlIssuer{
			XMLName: xml.Name{Local: "saml:Issuer"},
			Format:  "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:   p.cfg.EntityID,
		},
	}
	url, err := authReq.URL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, url, http.StatusFound)
	p.er.Record("saml auth request")
}

func (p *Provider) HandleCallback(w http.ResponseWriter, req *http.Request) {
	p.er.Record("saml auth callback")
	req.ParseForm()
	if req.Form.Get("logout") != "" {
		p.cm.ClearCookies(w)
		w.Write([]byte("logout successful"))
		return
	}

	if req.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusForbidden)
		return
	}

	b, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	root := doc.Root()
	if root == nil {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	// Assertion is the only part that's signed. So, we ignore everything
	// else.
	assertion := root.FindElement("./Assertion")
	if assertion == nil {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	v, err := p.dsigCtx.Validate(assertion)
	if err != nil {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	id := findElementAttr(v, "./Subject/SubjectConfirmation/SubjectConfirmationData", "InResponseTo")

	p.mu.Lock()
	for k, v := range p.states {
		if time.Since(v.Created) > 5*time.Minute {
			delete(p.states, k)
		}
	}
	state, ok := p.states[id]
	if ok {
		delete(p.states, id)
	}
	p.mu.Unlock()

	if !ok {
		p.er.Record("invalid state")
		http.Error(w, "timeout", http.StatusForbidden)
		return
	}

	if r := findElementAttr(v, "./Subject/SubjectConfirmation/SubjectConfirmationData", "Recipient"); r != p.cfg.ACSURL {
		http.Error(w, "invalid saml response", http.StatusForbidden)
		return
	}
	u, err := url.Parse(p.cfg.ACSURL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	self := "https://" + host + "/"
	if aud := findElementText(v, "./Conditions/AudienceRestriction/Audience"); aud != self {
		http.Error(w, "invalid saml response", http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339Nano, findElementAttr(v, "./Conditions", "NotBefore")); err != nil || t.After(now) {
		http.Error(w, "invalid saml response", http.StatusForbidden)
		return
	}
	if t, err := time.Parse(time.RFC3339Nano, findElementAttr(v, "./Conditions", "NotOnOrAfter")); err != nil || t.Before(now) {
		http.Error(w, "invalid saml response", http.StatusForbidden)
		return
	}
	sub := findElementText(v, "./Subject/NameID")
	if sub == "" {
		http.Error(w, "invalid saml response", http.StatusForbidden)
		return
	}

	if err := p.cm.SetAuthTokenCookie(w, sub, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, state.OriginalURL, http.StatusFound)
}

func readCerts(s string) ([]*x509.Certificate, error) {
	var b []byte
	if len(s) > 0 && s[0] == '/' {
		var err error
		if b, err = os.ReadFile(s); err != nil {
			return nil, err
		}
	} else {
		b = []byte(s)
	}
	var certs []*x509.Certificate
	for len(b) > 0 {
		block, rest := pem.Decode(b)
		b = rest
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func findElementText(e *etree.Element, p string) string {
	v := e.FindElement(p)
	if v == nil {
		return ""
	}
	return v.Text()
}

func findElementAttr(e *etree.Element, p, a string) string {
	v := e.FindElement(p)
	if v == nil {
		return ""
	}
	attr := v.SelectAttr(a)
	if attr == nil {
		return ""
	}
	return attr.Value
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

func (r *samlAuthnRequest) URL() (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	s, err := xml.Marshal(r)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(s); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	url, err := url.Parse(r.Destination)
	if err != nil {
		return "", err
	}
	q := url.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	url.RawQuery = q.Encode()

	return url.String(), nil
}
