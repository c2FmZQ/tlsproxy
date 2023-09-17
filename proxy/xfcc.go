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

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
)

const xFCCHeader = "x-forwarded-client-cert"

func addXFCCHeader(req *http.Request, which []string) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return
	}
	var fields []string
	for _, f := range which {
		switch strings.ToLower(f) {
		case "cert":
			fields = append(fields, "Cert="+encodeXFCC(url.QueryEscape(
				string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: req.TLS.PeerCertificates[0].Raw,
				})),
			)))
		case "chain":
			for _, chain := range req.TLS.VerifiedChains {
				var buf bytes.Buffer
				for _, cert := range chain {
					pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
				}
				fields = append(fields, "Chain="+encodeXFCC(url.QueryEscape(buf.String())))
			}
		case "hash":
			h := sha256.Sum256(req.TLS.PeerCertificates[0].Raw)
			fields = append(fields, "Hash="+encodeXFCC(hex.EncodeToString(h[:])))
		case "subject":
			fields = append(fields, "Subject="+encodeXFCCSubject(req.TLS.PeerCertificates[0].Subject.String()))
		case "uri":
			for _, uri := range req.TLS.PeerCertificates[0].URIs {
				fields = append(fields, "URI="+encodeXFCC(url.QueryEscape(uri.String())))
			}
		case "dns":
			for _, n := range req.TLS.PeerCertificates[0].DNSNames {
				fields = append(fields, "DNS="+encodeXFCC(url.QueryEscape(n)))
			}
		}
	}
	req.Header.Set(xFCCHeader, strings.Join(fields, ";"))
}

func encodeXFCCSubject(input string) string {
	var parts []string
	var esc bool
	s := &strings.Builder{}
	for _, r := range input {
		if r == ',' && !esc {
			parts = append(parts, s.String())
			s.Reset()
			esc = false
			continue
		}

		esc = !esc && r == '\\'
		s.WriteRune(r)
	}
	if s.Len() > 0 {
		parts = append(parts, s.String())
	}
	return encodeXFCC("/" + strings.Join(parts, "/"))
}

func encodeXFCC(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, `"`, `\"`)
	if strings.ContainsAny(s, ",;=") {
		s = `"` + s + `"`
	}
	return s
}
