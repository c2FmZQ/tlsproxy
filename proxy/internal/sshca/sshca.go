// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

// Package sshca implements a simple certificate authority for SSH.
package sshca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/tpm"
	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki/keys"
)

const (
	defaultCertsLifetime    = 10 * time.Minute
	defaultMaxCertsLifetime = 7 * 24 * time.Hour
)

//go:embed cert.html
var certHTML string
var certTemplate *template.Template

func init() {
	certTemplate = template.Must(template.New("ssh-cert").Parse(certHTML))
}

type defaultLogger struct{}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// Options are used to configure the CA.
type Options struct {
	// Name is the name of the CA.
	Name string `yaml:"name"`
	// KeyType is type of cryptographic key to use with this CA. Valid
	// values are: ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519,
	// rsa-2048, rsa-3072, and rsa-4096.
	KeyType string `yaml:"keyType,omitempty"`
	// PublicKeyEndpoint is the URL where the CA's public key is published.
	PublicKeyEndpoint string `yaml:"publicKeyEndpoint"`
	// CertificateEndpoint is the URL where certificates are issued. It
	// receives a public key in a POST request and returns a certificate.
	CertificateEndpoint string `yaml:"certificateEndpoint"`
	// MaximumCertificateLifetime specified the maximum certificate
	// lifetime. The default value is 1 week.
	MaximumCertificateLifetime time.Duration `yaml:"maximumCertificateLifetime,omitempty"`
	// TPM is used for hardware-backed keys.
	TPM *tpm.TPM
	// Store is used to store the PKI manager's data.
	Store *storage.Storage
	// EventRecorder is used to record events.
	EventRecorder interface {
		Record(string)
	}
	Logger interface {
		Errorf(format string, args ...any)
	}
}

// New returns a new initialized CA.
func New(opts Options) (*SSHCA, error) {
	if opts.Logger == nil {
		opts.Logger = defaultLogger{}
	}
	ca := &SSHCA{
		opts:   opts,
		caFile: "sshca-" + url.PathEscape(opts.Name),
	}
	if ca.opts.KeyType == "" {
		ca.opts.KeyType = "ecdsa-p256"
	}
	ca.opts.Store.CreateEmptyFile(ca.caFile, &certificateAuthority{})
	if err := ca.initCA(); err != nil {
		return nil, err
	}
	return ca, nil
}

// SSHCA implements a simple certificate authority for SSH keys.
type SSHCA struct {
	opts   Options
	caFile string
	mu     sync.Mutex
	db     *certificateAuthority
	signer ssh.Signer
}

type certificateAuthority struct {
	Name       string
	PrivateKey []byte
}

func (ca *SSHCA) open() (func(commit bool, errp *error) error, error) {
	commit, err := ca.opts.Store.OpenForUpdate(ca.caFile, &ca.db)
	if err != nil {
		return nil, err
	}
	return commit, nil
}

func (ca *SSHCA) initCA() (retErr error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	commit, err := ca.open()
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
	if ca.db == nil {
		ca.db = &certificateAuthority{
			Name: ca.opts.Name,
		}
		changed = true
	}

	if len(ca.db.PrivateKey) == 0 {
		_, keyBytes, err := ca.generateKey(ca.opts.KeyType)
		if err != nil {
			return err
		}
		ca.db.PrivateKey = keyBytes
		changed = true
	}

	key, err := ca.parseKeyBytes(ca.db.PrivateKey)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return err
	}
	ca.signer = signer

	return commit(changed, nil)
}

func (ca *SSHCA) generateKey(keyType string) (any, []byte, error) {
	if ca.opts.TPM != nil {
		switch kt := strings.ToLower(keyType); kt {
		case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
			var crv elliptic.Curve
			switch kt {
			case "ecdsa-p256":
				crv = elliptic.P256()
			case "ecdsa-p384":
				crv = elliptic.P384()
			case "ecdsa-p521":
				crv = elliptic.P521()
			}
			key, err := ca.opts.TPM.CreateKey(tpm.WithECC(crv))
			if err != nil {
				return nil, nil, err
			}
			keyBytes, err := key.Marshal()
			if err != nil {
				return nil, nil, err
			}
			return key, keyBytes, nil

		case "rsa-2048", "rsa-3072", "rsa-4096", "rsa-8192":
			var bits int
			switch kt {
			case "rsa-2048":
				bits = 2048
			case "rsa-3072":
				bits = 3072
			case "rsa-4096":
				bits = 4096
			case "rsa-8192":
				bits = 8192
			}
			key, err := ca.opts.TPM.CreateKey(tpm.WithRSA(bits))
			if err != nil {
				return nil, nil, err
			}
			keyBytes, err := key.Marshal()
			if err != nil {
				return nil, nil, err
			}
			return key, keyBytes, nil

		default:
			return nil, nil, fmt.Errorf("unexpected key type: %q", keyType)
		}
	}
	key, err := keys.GenerateKey(keyType)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	return key, keyBytes, nil
}

func (ca *SSHCA) parseKeyBytes(b []byte) (any, error) {
	if ca.opts.TPM != nil {
		return ca.opts.TPM.UnmarshalKey(b)
	}
	return x509.ParsePKCS8PrivateKey(b)
}

func (ca *SSHCA) ServePublicKey(w http.ResponseWriter, req *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.signer == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := ssh.MarshalAuthorizedKey(ca.signer.PublicKey())
	w.Header().Set("cache-control", "public, max-age=86400")
	w.Header().Set("content-type", "text/plain")
	w.Header().Set("content-length", fmt.Sprintf("%d", len(out)))
	w.Write(out)
}

func (ca *SSHCA) ServeCertificate(w http.ResponseWriter, req *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.signer == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var email string
	if claims := fromctx.Claims(req.Context()); claims != nil {
		if e, ok := claims["email"].(string); ok && e != "" {
			email = e
		}
	}
	if email == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		w.Header().Set("cache-control", "private")
		w.Header().Set("content-type", "text/html")

		data := struct {
			Email string
			Name  string
			CA    string
		}{
			Email: email,
			Name:  ca.opts.Name,
			CA:    string(ssh.MarshalAuthorizedKey(ca.signer.PublicKey())),
		}
		w.Header().Set("X-Frame-Options", "DENY")
		if err := certTemplate.Execute(w, data); err != nil {
			ca.opts.Logger.Errorf("ERR cert.html: %v", err)
		}
		return
	}
	if req.Method != http.MethodPost {
		ca.opts.Logger.Errorf("ERR method: %v", req.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ttl := defaultCertsLifetime
	var key []byte

	switch ct := req.Header.Get("content-type"); ct {
	case "text/plain":
		defer req.Body.Close()
		body, err := io.ReadAll(&io.LimitedReader{R: req.Body, N: 102400})
		if err != nil {
			ca.opts.Logger.Errorf("ERR body: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		key = body

	case "application/x-www-form-urlencoded":
		req.ParseForm()
		key = []byte(req.PostForm.Get("key"))
		if t := req.PostForm.Get("ttl"); t != "" {
			tt, err := strconv.Atoi(t)
			if err != nil {
				ca.opts.Logger.Errorf("ERR ttl: %v", err)
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			ttl = time.Second * time.Duration(tt)
		}

	default:
		ca.opts.Logger.Errorf("ERR content-type: %q", ct)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if ca.opts.MaximumCertificateLifetime != 0 {
		ttl = min(ca.opts.MaximumCertificateLifetime, ttl)
	} else {
		ttl = min(defaultMaxCertsLifetime, ttl)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		ca.opts.Logger.Errorf("ERR key: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c, ok := pub.(*ssh.Certificate); ok {
		pub = c.Key
	}
	switch kt := pub.Type(); kt {
	case ssh.KeyAlgoRSA:
	case ssh.KeyAlgoDSA:
	case ssh.KeyAlgoECDSA256:
	case ssh.KeyAlgoSKECDSA256:
	case ssh.KeyAlgoECDSA384:
	case ssh.KeyAlgoECDSA521:
	case ssh.KeyAlgoED25519:
	case ssh.KeyAlgoSKED25519:
	default:
		ca.opts.Logger.Errorf("ERR unexpected ssh key type: %v", kt)
		http.Error(w, "unexpected key type", http.StatusInternalServerError)
		return
	}
	rnd := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, rnd); err != nil {
		ca.opts.Logger.Errorf("ERR rand: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(rnd),
		CertType:        ssh.UserCert,
		KeyId:           email,
		ValidPrincipals: []string{email},
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		ca.opts.Logger.Errorf("ERR SignCert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ca.opts.EventRecorder != nil {
		ca.opts.EventRecorder.Record("ssh certificate issued")
	}

	out := ssh.MarshalAuthorizedKey(cert)
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("content-type", "text/plain")
	w.Header().Set("content-length", fmt.Sprintf("%d", len(out)))
	w.Write(out)
}
