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

//go:generate ./build-wasm.sh

package pki

import (
	"compress/bzip2"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

//go:embed certs.html
var embedCerts string
var certsTemplate *template.Template

//go:embed certs.js style.css pki.wasm.bz2 wasm_exec.js
var staticFiles embed.FS
var staticEtags map[string]string

func init() {
	certsTemplate = template.Must(template.New("pki-certs").Parse(embedCerts))
	staticEtags = make(map[string]string)
	d, err := staticFiles.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, e := range d {
		b, err := staticFiles.ReadFile(e.Name())
		if err != nil {
			panic(err)
		}
		h := sha256.Sum256(b)
		staticEtags[e.Name()] = `"` + hex.EncodeToString(h[:]) + `"`
	}
}

// ServeCACert sends the CA's certificate.
func (m *PKIManager) ServeCACert(w http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.db == nil || m.db.CACert == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("cache-control", "public, max-age=86400")
	if strings.HasSuffix(req.URL.Path, ".pem") {
		w.Header().Set("content-type", "application/x-pem-file")
		out := m.db.CACert.pem()
		for _, c := range m.db.DelegateCerts {
			out = append(out, c.pem()...)
		}
		etag(w, req, out)
		return
	}
	w.Header().Set("content-type", "application/x-x509-ca-cert")
	out := m.db.CACert.Raw
	for _, c := range m.db.DelegateCerts {
		out = append(out, c.Raw...)
	}
	etag(w, req, out)
}

// ServeCRL sends the revocation list.
func (m *PKIManager) ServeCRL(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("cache-control", "public, max-age=1800")
	if strings.HasSuffix(req.URL.Path, ".pem") {
		b, err := m.RevocationListPEM()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/x-pem-file")
		etag(w, req, b)
		return
	}
	_, b, err := m.RevocationList()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/x-pkcs7-crl")
	etag(w, req, b)
}

// ServeOCSP implements the OCSP protocol for this CA.
// https://www.rfc-editor.org/rfc/rfc6960.html
func (m *PKIManager) ServeOCSP(w http.ResponseWriter, req *http.Request) {
	var raw []byte
	switch req.Method {
	case http.MethodGet:
		// https://www.rfc-editor.org/rfc/rfc6960.html#page-30
		off := strings.LastIndex(req.URL.Path, "/")
		if off < 0 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		data, err := url.PathUnescape(req.URL.Path[off+1:])
		if err != nil {
			m.opts.Logger.Errorf("ERR url.PathUnescape: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		// Accept std and url base64 encoding, with or without padding.
		data = strings.ReplaceAll(data, " ", "-")
		data = strings.ReplaceAll(data, "+", "-")
		data = strings.ReplaceAll(data, "/", "_")
		data = strings.TrimRight(data, "=")
		if raw, err = base64.RawURLEncoding.DecodeString(data); err != nil {
			m.opts.Logger.Errorf("ERR base64: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		// https://www.rfc-editor.org/rfc/rfc6960.html#page-30
		if req.Header.Get("content-type") != "application/ocsp-request" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		const maxSize = 4096
		var err error
		if raw, err = io.ReadAll(&io.LimitedReader{R: req.Body, N: maxSize}); err != nil || len(raw) == maxSize {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ocspReq, err := ocsp.ParseRequest(raw)
	if err != nil {
		m.opts.Logger.Errorf("ERR ocsp.ParseRequest: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	resp, err := m.OCSPResponse(ocspReq)
	if err != nil {
		m.opts.Logger.Errorf("ERR OCSPResponse: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("cache-control", "public, max-age=1800")
	w.Header().Set("content-type", "application/ocsp-response")
	w.Write(resp)
}

func (m *PKIManager) ServeCertificateManagement(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	enableAdmin := req.Form.Get("admin")
	claims := m.opts.ClaimsFromCtx(req.Context())
	if claims == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	email, _ := claims["email"].(string)
	isAdmin := enableAdmin != "" && slices.Contains(m.opts.Admins, email)

	mode := req.Form.Get("get")
	switch mode {
	case "requestCert":
		m.handleRequestCert(w, req)
		return
	case "revokeCert":
		m.handleRevokeCert(w, req, isAdmin)
		return
	case "downloadCert":
		m.handleDownloadCert(w, req)
		return
	case "static":
		m.handleStaticFile(w, req)
		return
	default:
		m.opts.Logger.Errorf("ERR unexpected mode: %v", mode)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	case "":
		// Continue below
	}
	statusFilter := strings.ToLower(req.Form.Get("status"))
	ownerFilter := strings.ToLower(req.Form.Get("owner"))

	m.mu.Lock()
	defer m.mu.Unlock()

	var currentSN string
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		currentSN = bytesToHex(req.TLS.PeerCertificates[0].SerialNumber.Bytes())
	}

	if m.db == nil || m.db.CACert == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	caCert, err := m.db.CACert.parse()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type cert struct {
		SN             string
		PublicKey      string
		Subject        string
		EmailAddresses []string
		DNSNames       []string
		URIs           []*url.URL
		NotBefore      string
		NotAfter       string
		RevocationTime string
		ExtKeyUsage    string
		IsCA           bool
		Status         string
		UsedNow        bool
		CanRevoke      bool
	}
	certs := make([]cert, 0, len(m.db.IssuedCerts))
	now := time.Now().UTC()

	for _, ic := range m.db.IssuedCerts {
		c, err := ic.parse()
		if err != nil {
			m.opts.Logger.Errorf("ERR x509.ParseCertificate: %v", err)
			continue
		}
		if ownerFilter != "all" && !slices.Contains(c.EmailAddresses, email) {
			continue
		}
		var revTime time.Time
		if r := ic.Revocation; r != nil {
			revTime = r.Time
		}
		status := "Valid"
		if !revTime.IsZero() {
			status = "Revoked"
		} else if now.After(c.NotAfter) {
			status = "Expired"
		}
		if (statusFilter == "" || statusFilter == "valid") && status != "Valid" {
			continue
		}
		if statusFilter == "revoked" && status != "Revoked" {
			continue
		}
		if statusFilter == "expired" && status != "Expired" {
			continue
		}
		var eku []string
		for _, v := range c.ExtKeyUsage {
			switch v {
			case x509.ExtKeyUsageServerAuth:
				eku = append(eku, "ServerAuth")
			case x509.ExtKeyUsageClientAuth:
				eku = append(eku, "ClientAuth")
			case x509.ExtKeyUsageOCSPSigning:
				eku = append(eku, "OCSPSigning")
			}
		}
		pubKeyBytes, err := publicKeyFromCert(c)
		if err != nil {
			m.opts.Logger.Errorf("ERR publicKeyFromCert: %v", err)
			continue
		}
		certs = append(certs, cert{
			SN:             ic.SerialNumber,
			PublicKey:      c.PublicKeyAlgorithm.String() + " " + bytesToHex(pubKeyBytes),
			Subject:        c.Subject.String(),
			EmailAddresses: c.EmailAddresses,
			DNSNames:       c.DNSNames,
			URIs:           c.URIs,
			NotBefore:      c.NotBefore.Format(time.DateTime),
			NotAfter:       c.NotAfter.Format(time.DateTime),
			RevocationTime: revTime.Format(time.DateTime),
			ExtKeyUsage:    strings.Join(eku, ", "),
			IsCA:           c.IsCA,
			Status:         status,
			UsedNow:        currentSN == ic.SerialNumber,
			CanRevoke:      !c.IsCA && (isAdmin || slices.Contains(c.EmailAddresses, email)),
		})
	}
	slices.Reverse(certs)

	data := struct {
		Status         string
		Owner          string
		Email          string
		CASubject      string
		CASN           string
		CASubjectKeyId string
		Certs          []cert
	}{
		Status:         statusFilter,
		Owner:          ownerFilter,
		Email:          email,
		CASubject:      caCert.Subject.String(),
		CASN:           bytesToHex(caCert.SerialNumber.Bytes()),
		CASubjectKeyId: bytesToHex(caCert.SubjectKeyId),
		Certs:          certs,
	}
	w.Header().Set("X-Frame-Options", "DENY")
	certsTemplate.Execute(w, data)
}

func (m *PKIManager) handleRequestCert(w http.ResponseWriter, req *http.Request) {
	claims := m.opts.ClaimsFromCtx(req.Context())
	if claims == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	email, _ := claims["email"].(string)

	if req.Method != http.MethodPost {
		m.opts.Logger.Errorf("ERR method: %v", req.Method)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if v := req.Header.Get("x-csrf-check"); v != "1" {
		m.opts.Logger.Errorf("ERR x-csrf-check: %v", v)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if ct := req.Header.Get("content-type"); ct != "application/x-pem-file" {
		m.opts.Logger.Errorf("ERR content-type: %v", ct)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer req.Body.Close()
	body, err := io.ReadAll(&io.LimitedReader{R: req.Body, N: 102400})
	if err != nil {
		m.opts.Logger.Errorf("ERR body: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	block, _ := pem.Decode(body)
	if block == nil {
		m.opts.Logger.Errorf("ERR no pem block")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	in, err := m.ValidateCertificateRequest(block.Bytes)
	if err != nil {
		m.opts.Logger.Errorf("ERR ValidateCertificateRequest: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	cr := &x509.CertificateRequest{
		PublicKeyAlgorithm: in.PublicKeyAlgorithm,
		PublicKey:          in.PublicKey,
		Subject:            pkix.Name{CommonName: email},
		EmailAddresses: []string{
			email,
		},
		DNSNames: in.DNSNames,
	}
	if in.Subject.CommonName != "" {
		cr.Subject.CommonName += "::" + in.Subject.CommonName
	}
	cert, err := m.IssueCertificate(cr)
	if err != nil {
		m.opts.Logger.Errorf("ERR body: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"result": "ok",
		"cert":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})),
	})
}

func (m *PKIManager) handleRevokeCert(w http.ResponseWriter, req *http.Request, isAdmin bool) {
	claims := m.opts.ClaimsFromCtx(req.Context())
	if claims == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	email, _ := claims["email"].(string)

	if req.Method != http.MethodPost {
		m.opts.Logger.Errorf("ERR method: %v", req.Method)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if v := req.Header.Get("x-csrf-check"); v != "1" {
		m.opts.Logger.Errorf("ERR x-csrf-check: %v", v)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	c, err := m.findCert(req.Form.Get("sn"))
	if err != nil {
		m.opts.Logger.Errorf("ERR findCert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	if now.After(c.NotAfter) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !isAdmin && !slices.Contains(c.EmailAddresses, email) {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"result": "permission denied",
		})
		return
	}
	if err := m.RevokeCertificate(c.SerialNumber, RevokeReasonUnspecified); err != nil {
		m.opts.Logger.Errorf("ERR m.RevokeCertificate: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"result": "ok",
	})
}

func (m *PKIManager) handleDownloadCert(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		m.opts.Logger.Errorf("ERR method: %v", req.Method)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	sn := req.Form.Get("sn")
	c, err := m.findCert(sn)
	if err != nil {
		m.opts.Logger.Errorf("ERR findCert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/x-pem-file")
	w.Header().Set("content-disposition", "attachment; filename=\""+strings.ReplaceAll(sn, ":", "")+".pem\"")
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func (m *PKIManager) handleStaticFile(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		m.opts.Logger.Errorf("ERR method: %v", req.Method)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	file := req.Form.Get("file")
	r, err := staticFiles.Open(file)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer r.Close()
	var rr io.Reader = r
	if strings.HasSuffix(file, ".bz2") {
		rr = bzip2.NewReader(r)
	}
	if file == "pki.wasm.bz2" {
		w.Header().Set("content-type", "application/wasm")
	} else if t := mime.TypeByExtension(filepath.Ext(file)); t != "" {
		w.Header().Set("content-type", t)
	}
	etag, ok := staticEtags[file]
	if ok {
		w.Header().Set("Etag", etag)
		if e := req.Header.Get("If-None-Match"); e == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	io.Copy(w, rr)
}

func (m *PKIManager) findCert(sn string) (*x509.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.db == nil || m.db.CACert == nil {
		return nil, errNotFound
	}
	i := slices.IndexFunc(m.db.IssuedCerts, func(c *certificate) bool {
		return c.SerialNumber == sn
	})
	if i < 0 {
		return nil, errNotFound
	}
	if m.db.IssuedCerts[i].Revocation != nil {
		return nil, errNotFound
	}
	return m.db.IssuedCerts[i].parse()
}

func etag(w http.ResponseWriter, req *http.Request, body []byte) {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Etag", etag)

	if e := req.Header.Get("If-None-Match"); e == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}
