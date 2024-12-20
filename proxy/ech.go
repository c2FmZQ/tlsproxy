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
	"crypto/tls"
	"encoding/base64"
	"log"
	"time"

	"github.com/c2FmZQ/ech"
)

const echFile = "ech"

type echKey struct {
	CreationTime time.Time `json:"creationTime"`
	PublicName   string    `json:"publicName"`
	Config       []byte    `json:"config"`
	PrivateKey   []byte    `json:"privateKey"`
	SendAsRetry  bool      `json:"sendAsRetry"`
}

func (p *Proxy) initECH() (retErr error) {
	publicName := p.defServerName
	if len(publicName) == 0 || p.cfg.EnableECH == nil || !*p.cfg.EnableECH {
		return nil
	}
	var echKeys []echKey
	p.store.CreateEmptyFile(echFile, &echKeys)

	commit, err := p.store.OpenForUpdate(echFile, &echKeys)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)

	if len(echKeys) == 0 || echKeys[0].PublicName != publicName {
		id := uint8(len(echKeys) + 1)
		key, cfg, err := ech.NewConfig(id, []byte(publicName))
		if err != nil {
			return err
		}
		echKeys = append([]echKey{{
			CreationTime: time.Now().UTC(),
			PublicName:   publicName,
			Config:       cfg,
			PrivateKey:   key.Bytes(),
			SendAsRetry:  true,
		}}, echKeys...)
		if err := commit(true, nil); err != nil {
			return err
		}
	}
	p.echKeys = make([]tls.EncryptedClientHelloKey, 0, len(echKeys))
	for _, k := range echKeys {
		p.echKeys = append(p.echKeys, tls.EncryptedClientHelloKey{
			Config:      k.Config,
			PrivateKey:  k.PrivateKey,
			SendAsRetry: k.SendAsRetry,
		})
	}
	configList, err := ech.ConfigList([]ech.Config{p.echKeys[0].Config})
	if err != nil {
		return err
	}
	log.Printf("INF ECH ConfigList: %s", base64.StdEncoding.EncodeToString(configList))
	return nil
}
