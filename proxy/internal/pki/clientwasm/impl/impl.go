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

package impl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki/keys"
)

var (
	privateKeys map[int]keyData
)

type keyData struct {
	key      crypto.PrivateKey
	format   string
	password string
}

func MakeCSR(id int, keyType, format, label, dnsname, password string) ([]byte, error) {
	privKey, err := keys.GenerateKey(keyType)
	if err != nil {
		return nil, err
	}
	if privateKeys == nil {
		privateKeys = make(map[int]keyData)
	}
	privateKeys[id] = keyData{
		key:      privKey,
		format:   format,
		password: password,
	}

	templ := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: label},
	}
	if dnsname != "" {
		templ.DNSNames = strings.Fields(strings.ReplaceAll(dnsname, ",", " "))
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, templ, privKey)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificateRequest: %v\n", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}), nil
}

func MakeResponse(id int, pemCert string) ([]byte, string, string, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", "", errors.New("invalid pem certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", "", errors.New("invalid certificate")
	}
	sn := hex.EncodeToString(cert.SerialNumber.Bytes())
	kd, ok := privateKeys[id]
	if !ok {
		return nil, "", "", errors.New("invalid id")
	}
	delete(privateKeys, id)
	switch kd.format {
	case "gpg":
		b, err := x509.MarshalPKCS8PrivateKey(kd.key)
		if err != nil {
			return nil, "", "", fmt.Errorf("x509.MarshalPKCS8PrivateKey: %v\n", err)
		}
		var buf bytes.Buffer
		w, err := openpgp.SymmetricallyEncrypt(&buf, []byte(kd.password), &openpgp.FileHints{FileName: sn + ".pem", ModTime: cert.NotBefore}, nil)
		if err != nil {
			return nil, "", "", fmt.Errorf("openpgp.SymmetricallyEncrypt: %v\n", err)
		}
		if err := pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: b}); err != nil {
			return nil, "", "", fmt.Errorf("pem.Encode: %v\n", err)
		}
		if _, err := w.Write([]byte(pemCert)); err != nil {
			return nil, "", "", fmt.Errorf("Write: %v\n", err)
		}
		if err := w.Close(); err != nil {
			return nil, "", "", fmt.Errorf("Close: %v\n", err)
		}
		return buf.Bytes(), "application/octet-stream", sn + ".pem.gpg", nil

	case "p12":
		enc := pkcs12.Modern.WithIterations(250000)
		p12, err := enc.Encode(kd.key, cert, nil, kd.password)
		if err != nil {
			return nil, "", "", fmt.Errorf("pkcs12.Encode: %v", err)
		}
		return p12, "application/x-pkcs12", sn + ".p12", nil

	default:
		return nil, "", "", errors.New("unexpected format")
	}
}
