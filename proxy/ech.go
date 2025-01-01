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

package proxy

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/c2FmZQ/ech"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cloudflare"
)

const echFile = "ech"

type echKey struct {
	CreationTime time.Time `json:"creationTime"`
	PublicName   string    `json:"publicName"`
	Config       []byte    `json:"config"`
	PrivateKey   []byte    `json:"privateKey"`
}

func (p *Proxy) initECH() (retErr error) {
	if p.cfg.ECH == nil || p.cfg.ECH.PublicName == "" {
		return nil
	}
	var echKeys []echKey
	p.store.CreateEmptyFile(echFile, &echKeys)

	commit, err := p.store.OpenForUpdate(echFile, &echKeys)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)

	if len(echKeys) > 5 {
		echKeys = echKeys[:5]
	}
	if len(echKeys) == 0 || echKeys[0].PublicName != p.cfg.ECH.PublicName || (p.cfg.ECH.Interval > 0 && time.Since(echKeys[0].CreationTime) > p.cfg.ECH.Interval) {
		idExists := func(id uint8) bool {
			return slices.IndexFunc(echKeys, func(k echKey) bool {
				s, err := ech.Config(k.Config).Spec()
				if err != nil {
					return false
				}
				return s.ID == id
			}) != -1
		}
		var id uint8
		for {
			b := make([]byte, 1)
			if _, err := io.ReadFull(rand.Reader, b); err != nil {
				return err
			}
			if id = b[0]; !idExists(id) {
				break
			}
		}
		key, cfg, err := ech.NewConfig(id, []byte(p.cfg.ECH.PublicName))
		if err != nil {
			return err
		}
		echKeys = append([]echKey{{
			CreationTime: time.Now().UTC(),
			PublicName:   p.cfg.ECH.PublicName,
			Config:       cfg,
			PrivateKey:   key.Bytes(),
		}}, echKeys...)
		if err := commit(true, nil); err != nil {
			return err
		}
	}
	p.echKeys = make([]tls.EncryptedClientHelloKey, 0, len(echKeys))
	for i, k := range echKeys {
		p.echKeys = append(p.echKeys, tls.EncryptedClientHelloKey{
			Config:      k.Config,
			PrivateKey:  k.PrivateKey,
			SendAsRetry: i == 0,
		})
	}
	configList, err := ech.ConfigList([]ech.Config{p.echKeys[0].Config})
	if err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString(configList)
	log.Printf("INF ECH ConfigList: %s", b64)
	if len(p.cfg.ECH.Cloudflare) > 0 {
		go cloudflare.UpdateECH(p.cfg.ECH.Cloudflare, b64, p.logErrorF)
	}
	return nil
}

func (p *Proxy) serveECHConfigList(w http.ResponseWriter, req *http.Request) {
	if len(p.echKeys) == 0 {
		http.NotFound(w, req)
		return
	}
	configList, err := ech.ConfigList([]ech.Config{p.echKeys[0].Config})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	enc := base64.NewEncoder(base64.StdEncoding, w)
	enc.Write(configList)
	enc.Close()
}
