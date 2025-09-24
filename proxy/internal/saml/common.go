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
	"encoding/base64"
	"encoding/xml"
	"net/url"
)

type SAMLAuthnRequest struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	XMLNS                       string   `xml:"xmlns,attr"`
	XMLNSSAML                   string   `xml:"xmlns:saml,attr"`
	ID                          string   `xml:",attr"`
	Version                     string   `xml:",attr"`
	IssueInstant                string   `xml:",attr"`
	Destination                 string   `xml:",attr"`
	ProtocolBinding             string   `xml:",attr"`
	AssertionConsumerServiceURL string   `xml:",attr"`
	Issuer                      samlIssuer
}

type samlIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

func (r *SAMLAuthnRequest) URL() (string, error) {
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
