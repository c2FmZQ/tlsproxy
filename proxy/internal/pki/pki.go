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

// Package pki implements a simple Public Key Infrastructure (PKI) manager that
// can issue and revoke X.509 certificates.
package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ocsp"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki/keys"
)

const (
	// https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3.1
	RevokeReasonUnspecified          = 0
	RevokeReasonKeyCompromise        = 1
	RevokeReasonCACompromise         = 2
	RevokeReasonAffiliationChanged   = 3
	RevokeReasonSuperseded           = 4
	RevokeReasonCessationOfOperation = 5
	RevokeReasonCertificateHold      = 6
	// value 7 is not used
	RevokeReasonRemoveFromCRL       = 8
	RevokeReasonPriviliegeWithDrawn = 9
	RevokeReasonAACompromise        = 10

	crlRefreshPeriod    = time.Hour
	caCertLifetime      = 10 * 365 * 24 * time.Hour
	caDelegateLifetime  = 10 * 24 * time.Hour
	issuedCertsLifetime = 10 * 365 * 24 * time.Hour
	maxNumCRL           = 128
)

var (
	errAlreadyExists = errors.New("already exists")
	errNotFound      = errors.New("not found")
)

// Options are used to configure the PKI manager.
type Options struct {
	// Name is the names of the PKI manager.
	Name string
	// KeyType is one of ed25519, rsa-2048, rsa-4096, ecdsa-p256, etc.
	// Defaults to ecdsa-p256.
	KeyType string
	// Endpoint is the URL that serves the PKI web pages.
	Endpoint string
	// IssuingCertificateURL is a list of URLs that serve the CA certificate.
	IssuingCertificateURL []string
	// CRLDistributionPoints is a list of URLs that server this CA's
	// Certificate Revocation List.
	CRLDistributionPoints []string
	// OCSPServer is a list of URLs that serve the Online Certificate Status
	// Protocol (OCSP) for this CA.
	// https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
	OCSPServer []string
	// Admins is the of users who are allowed to perform administrative
	// tasks.
	Admins []string
	// Store is used to store the PKI manager's data.
	Store *storage.Storage
	// EventRecorder is used to record events.
	EventRecorder interface {
		Record(string)
	}
	// ClaimsFromCtx returns jwt claims for the current user.
	ClaimsFromCtx func(context.Context) jwt.MapClaims
}

// New returns a new initialized PKI manager. The Certificate Authority's key
// and certificate are created the first time New is called for a given name.
func New(opts Options) (*PKIManager, error) {
	m := &PKIManager{
		opts:    opts,
		pkiFile: "pki-" + url.PathEscape(opts.Name),
	}
	if m.opts.KeyType == "" {
		m.opts.KeyType = "ecdsa-p256"
	}
	m.opts.Store.CreateEmptyFile(m.pkiFile, &certificateAuthority{})
	if err := m.initCA(); err != nil {
		return nil, err
	}
	return m, nil
}

// PKIManager implements a simple Public Key Infrastructure (PKI) manager that
// can issue and revoke X.509 certificates.
type PKIManager struct {
	opts    Options
	pkiFile string
	mu      sync.Mutex
	db      *certificateAuthority
}

type certificateAuthority struct {
	Name            string
	PrivateKey      []byte
	CACert          *certificate
	DelegateKey     []byte
	DelegateCerts   []*certificate
	IssuedCerts     []*certificate
	CRLNumber       int64
	RevocationLists []revocationList
	Revoked         map[string]bool
}

type certificate struct {
	SHA256       string
	SerialNumber string
	Raw          []byte
	Revocation   *revocation

	cert *x509.Certificate
}

func (c *certificate) parse() (*x509.Certificate, error) {
	if c.cert != nil {
		return c.cert, nil
	}
	cert, err := x509.ParseCertificate(c.Raw)
	if err != nil {
		return nil, err
	}
	c.cert = cert
	return c.cert, nil
}

func (c *certificate) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
}

func (c *certificate) revoke(code int) {
	c.Revocation = &revocation{
		Time:       time.Now().UTC().Truncate(time.Second),
		ReasonCode: code,
	}
}

type revocation struct {
	Time       time.Time
	ReasonCode int
}

type revocationList struct {
	RawCert []byte
	RawCRL  []byte
}

func (m *PKIManager) open() (func(commit bool, errp *error) error, error) {
	commit, err := m.opts.Store.OpenForUpdate(m.pkiFile, &m.db)
	if err != nil {
		return nil, err
	}
	return func(doCommit bool, errp *error) error {
		err := commit(doCommit, errp)
		wipe(m.db.PrivateKey)
		return err
	}, nil
}

func (m *PKIManager) initCA() (retErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	commit, err := m.open()
	if err != nil {
		return err
	}
	defer func() {
		commit(false, &retErr)
		if retErr == storage.ErrRolledBack {
			retErr = nil
		}
	}()
	var changed bool
	if m.db == nil {
		m.db = &certificateAuthority{
			Name: m.opts.Name,
		}
		changed = true
	}

	if len(m.db.PrivateKey) == 0 {
		privKey, err := keys.GenerateKey(m.opts.KeyType)
		if err != nil {
			return err
		}
		keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return fmt.Errorf("x509.MarshalPKCS8PrivateKey: %v", err)
		}
		m.db.PrivateKey = keyBytes
		changed = true
	}

	type privateKey interface {
		Public() crypto.PublicKey
	}
	pk, err := x509.ParsePKCS8PrivateKey(m.db.PrivateKey)
	if err != nil {
		return err
	}
	privKey, ok := pk.(privateKey)
	if !ok {
		return fmt.Errorf("unexpected private key type %T", pk)
	}

	now := time.Now().UTC()
	var needCert bool
	if m.db.CACert == nil {
		needCert = true
	} else {
		cert, err := m.db.CACert.parse()
		if err != nil {
			return err
		}
		if cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2).Before(now) {
			needCert = true
		}
	}

	if needCert {
		sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
		if err != nil {
			return err
		}
		templ := &x509.Certificate{
			SerialNumber:          sn,
			Issuer:                pkix.Name{CommonName: m.opts.Name},
			Subject:               pkix.Name{CommonName: m.opts.Name},
			NotBefore:             now,
			NotAfter:              now.Add(caCertLifetime),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        true,
			IssuingCertificateURL: m.opts.IssuingCertificateURL,
			CRLDistributionPoints: m.opts.CRLDistributionPoints,
			OCSPServer:            m.opts.OCSPServer,
		}
		raw, err := x509.CreateCertificate(rand.Reader, templ, templ, privKey.Public(), privKey)
		if err != nil {
			return fmt.Errorf("x509.CreateCertificate: %w", err)
		}
		h256 := sha256.Sum256(raw)

		c := &certificate{
			SHA256:       bytesToHex(h256[:]),
			SerialNumber: bytesToHex(sn.Bytes()),
			Raw:          raw,
		}
		// Keep most recent first.
		m.db.CACert = c
		m.db.IssuedCerts = append(m.db.IssuedCerts, c)
		changed = true
	}
	return commit(changed, nil)
}

func (m *PKIManager) maybeRotateDelegateCert() error {
	if m.db == nil {
		return errors.New("no ca")
	}
	now := time.Now().UTC()

	var needUpdate bool
	if len(m.db.DelegateCerts) == 0 {
		needUpdate = true
	} else {
		c, err := m.db.DelegateCerts[0].parse()
		if err != nil || c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore)/2).Before(now) {
			needUpdate = true
		}
	}
	if !needUpdate {
		return nil
	}

	caCert, err := m.db.CACert.parse()
	if err != nil {
		return err
	}

	delegateKey, err := keys.GenerateKey(m.opts.KeyType)
	if err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(delegateKey)
	if err != nil {
		return fmt.Errorf("x509.MarshalPKCS8PrivateKey: %v", err)
	}

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	if err != nil {
		return err
	}
	templ := &x509.Certificate{
		SerialNumber: sn,
		PublicKey:    delegateKey.(crypto.Signer).Public(),
		Issuer:       caCert.Subject,
		Subject:      pkix.Name{CommonName: m.opts.Name + " CRL OCSP"},
		NotBefore:    now,
		NotAfter:     now.Add(caDelegateLifetime),
		KeyUsage:     x509.KeyUsageCRLSign,
		ExtraExtensions: []pkix.Extension{
			// id-pkix-ocsp-nocheck
			pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}},
		},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IssuingCertificateURL: m.opts.IssuingCertificateURL,
		CRLDistributionPoints: m.opts.CRLDistributionPoints,
		OCSPServer:            m.opts.OCSPServer,
	}
	_, err = m.signCertificate(templ, func(c *certificate) error {
		m.db.DelegateKey = keyBytes
		old := m.db.DelegateCerts
		m.db.DelegateCerts = make([]*certificate, 0, 2)
		m.db.DelegateCerts = append(m.db.DelegateCerts, c)
		if len(old) > 0 {
			m.db.DelegateCerts = append(m.db.DelegateCerts, old[0])
		}
		return nil
	})
	return err
}

// RevocationListPEM returns the current revocation list, PEM encoded.
func (m *PKIManager) RevocationListPEM() ([]byte, error) {
	cert, crl, err := m.RevocationList()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	pem.Encode(&out, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	pem.Encode(&out, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	return out.Bytes(), nil
}

// RevocationList returns the current revocation list.
func (m *PKIManager) RevocationList() (cert, crl []byte, retErr error) {
	if err := m.maybeRotateDelegateCert(); err != nil {
		return nil, nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	commit, err := m.open()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		commit(false, &retErr)
		if retErr == storage.ErrRolledBack {
			retErr = nil
		}
	}()

	if m.db == nil {
		return nil, nil, errNotFound
	}
	now := time.Now().UTC()

	if len(m.db.RevocationLists) > 0 {
		var lastRevocation time.Time
		for _, c := range m.db.IssuedCerts {
			if c.Revocation != nil && c.Revocation.Time.After(lastRevocation) {
				lastRevocation = c.Revocation.Time
			}
		}
		last := m.db.RevocationLists[len(m.db.RevocationLists)-1]
		rl, err := x509.ParseRevocationList(last.RawCRL)
		if err != nil {
			return nil, nil, err
		}
		if !rl.ThisUpdate.Before(lastRevocation) && rl.NextUpdate.Add(crlRefreshPeriod/2).After(now) {
			return last.RawCert, rl.Raw, nil
		}
	}

	signCert, err := m.db.DelegateCerts[0].parse()
	if err != nil {
		return nil, nil, err
	}
	m.db.CRLNumber++
	rl := &x509.RevocationList{
		Issuer:     signCert.Subject,
		Number:     big.NewInt(m.db.CRLNumber),
		ThisUpdate: now,
		NextUpdate: now.Add(crlRefreshPeriod),
	}
	for _, c := range m.db.IssuedCerts {
		if c.Revocation == nil {
			continue
		}
		cert, err := c.parse()
		if err != nil {
			return nil, nil, err
		}
		if now.After(cert.NotAfter) {
			continue
		}
		rl.RevokedCertificateEntries = append(rl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: c.Revocation.Time,
			ReasonCode:     c.Revocation.ReasonCode,
		})
	}

	key, err := x509.ParsePKCS8PrivateKey(m.db.DelegateKey)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("invalid private key")
	}
	if crl, err = x509.CreateRevocationList(rand.Reader, rl, signCert, signer); err != nil {
		return nil, nil, err
	}
	m.db.RevocationLists = append(m.db.RevocationLists, revocationList{
		RawCert: signCert.Raw,
		RawCRL:  crl,
	})
	if n := len(m.db.RevocationLists) - maxNumCRL; n > 0 {
		m.db.RevocationLists = m.db.RevocationLists[n:]
	}

	if err := commit(true, nil); err != nil {
		return nil, nil, err
	}
	return signCert.Raw, crl, nil
}

// IsRevoked returns whether the certificate with this serial number of revoked.
func (m *PKIManager) IsRevoked(serialNumber *big.Int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return false
	}
	return m.db.Revoked[bytesToHex(serialNumber.Bytes())]
}

// OCSPResponse creates an OCSP Response from the given request.
func (m *PKIManager) OCSPResponse(req *ocsp.Request) ([]byte, error) {
	if !req.HashAlgorithm.Available() {
		return nil, errors.New("invalid hash algorithm")
	}
	if err := m.maybeRotateDelegateCert(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return nil, errNotFound
	}
	caCert, err := m.db.CACert.parse()
	if err != nil {
		return nil, err
	}
	delegateCert, err := m.db.DelegateCerts[0].parse()
	if err != nil {
		return nil, err
	}

	var pkInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(caCert.RawSubjectPublicKeyInfo, &pkInfo); err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(m.db.DelegateKey)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid private key")
	}

	h := req.HashAlgorithm.New()
	h.Write(pkInfo.PublicKey.RightAlign())
	pubKeyHash := h.Sum(nil)
	h.Reset()
	h.Write(caCert.RawSubject)
	subjectHash := h.Sum(nil)

	snh := bytesToHex(req.SerialNumber.Bytes())
	idx := slices.IndexFunc(m.db.IssuedCerts, func(c *certificate) bool {
		return c.SerialNumber == snh
	})

	now := time.Now().UTC()

	if bytes.Compare(req.IssuerNameHash, subjectHash[:]) != 0 || bytes.Compare(req.IssuerKeyHash, pubKeyHash[:]) != 0 {
		return ocsp.CreateResponse(caCert, delegateCert, ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   now,
			NextUpdate:   now.Add(crlRefreshPeriod),
			IssuerHash:   crypto.SHA256,
			Certificate:  delegateCert,
		}, signer)
	}
	if idx < 0 {
		return ocsp.CreateResponse(caCert, delegateCert, ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     req.SerialNumber,
			ThisUpdate:       now,
			NextUpdate:       now.Add(crlRefreshPeriod),
			RevokedAt:        now,
			RevocationReason: RevokeReasonCertificateHold,
			IssuerHash:       crypto.SHA256,
			Certificate:      delegateCert,
		}, signer)
	}
	if rev := m.db.IssuedCerts[idx].Revocation; rev != nil {
		return ocsp.CreateResponse(caCert, delegateCert, ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     req.SerialNumber,
			ThisUpdate:       now,
			NextUpdate:       now.Add(crlRefreshPeriod),
			RevokedAt:        rev.Time,
			RevocationReason: rev.ReasonCode,
			IssuerHash:       crypto.SHA256,
			Certificate:      delegateCert,
		}, signer)
	}
	return ocsp.CreateResponse(caCert, delegateCert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(crlRefreshPeriod),
		IssuerHash:   crypto.SHA256,
		Certificate:  delegateCert,
	}, signer)
}

// RevokeCertificate revokes the certificate with this serial number and set the
// reason code.
func (m *PKIManager) RevokeCertificate(serialNumber *big.Int, reasonCode int) (retErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	commit, err := m.open()
	if err != nil {
		return err
	}
	defer func() {
		commit(false, &retErr)
		if retErr == storage.ErrRolledBack {
			retErr = nil
		}
	}()

	if m.db == nil {
		return errNotFound
	}
	snh := bytesToHex(serialNumber.Bytes())
	for _, c := range m.db.IssuedCerts {
		if c.SerialNumber == snh {
			c.revoke(reasonCode)
			if m.db.Revoked == nil {
				m.db.Revoked = make(map[string]bool)
			}
			m.db.Revoked[snh] = true
			return commit(true, nil)
		}
	}
	return errNotFound
}

// CACert returns the CA's certificate.
func (m *PKIManager) CACert() (*x509.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.db == nil {
		return nil, errNotFound
	}
	return m.db.CACert.parse()
}

// ValidateCertificateRequest parses and validates a certificate signing
// request.
func (m *PKIManager) ValidateCertificateRequest(csr []byte) (*x509.CertificateRequest, error) {
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, err
	}
	return cr, nil
}

// IssueCertificate issues a new certificate.
func (m *PKIManager) IssueCertificate(cr *x509.CertificateRequest) (cert []byte, retErr error) {
	now := time.Now().UTC()
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	if err != nil {
		return nil, err
	}
	var eku []x509.ExtKeyUsage
	if len(cr.DNSNames) > 0 || len(cr.IPAddresses) > 0 {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	} else {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	templ := &x509.Certificate{
		Version:               cr.Version,
		SerialNumber:          sn,
		PublicKeyAlgorithm:    cr.PublicKeyAlgorithm,
		PublicKey:             cr.PublicKey,
		Subject:               cr.Subject,
		NotBefore:             now,
		NotAfter:              now.Add(issuedCertsLifetime),
		KeyUsage:              x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           eku,
		IssuingCertificateURL: m.opts.IssuingCertificateURL,
		CRLDistributionPoints: m.opts.CRLDistributionPoints,
		OCSPServer:            m.opts.OCSPServer,
		DNSNames:              cr.DNSNames,
		EmailAddresses:        cr.EmailAddresses,
		IPAddresses:           cr.IPAddresses,
		URIs:                  cr.URIs,
	}
	return m.signCertificate(templ, nil)
}

// signCertificate signs a new certificate.
func (m *PKIManager) signCertificate(cert *x509.Certificate, next func(*certificate) error) (raw []byte, retErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	commit, err := m.open()
	if err != nil {
		return nil, err
	}
	defer func() {
		commit(false, &retErr)
		if retErr == storage.ErrRolledBack {
			retErr = nil
		}
	}()

	if m.db == nil {
		return nil, errNotFound
	}
	caCert, err := m.db.CACert.parse()
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(m.db.PrivateKey)
	if err != nil {
		return nil, err
	}

	if raw, err = x509.CreateCertificate(rand.Reader, cert, caCert, cert.PublicKey, key); err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %v", err)
	}

	h256 := sha256.Sum256(raw)
	c := &certificate{
		SHA256:       bytesToHex(h256[:]),
		SerialNumber: bytesToHex(cert.SerialNumber.Bytes()),
		Raw:          raw,
	}
	m.db.IssuedCerts = append(m.db.IssuedCerts, c)

	if next != nil {
		if err := next(c); err != nil {
			return nil, err
		}
	}
	if err := commit(true, nil); err != nil {
		return nil, err
	}

	return raw, nil
}

func bytesToHex(b []byte) string {
	h := make([]string, 0, len(b))
	for _, v := range b {
		h = append(h, fmt.Sprintf("%02x", v))
	}
	return strings.Join(h, ":")
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
