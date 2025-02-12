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
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/ech/publish"
	"github.com/hashicorp/go-retryablehttp"
)

const echFile = "ech"

type echKey struct {
	CreationTime time.Time `json:"creationTime"`
	PublicName   string    `json:"publicName"`
	Config       []byte    `json:"config"`
	PrivateKey   []byte    `json:"privateKey"`
}

func (p *Proxy) rotateECH(forceCheck bool) (retErr error) {
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

	var changed bool
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
		if len(echKeys) > 5 {
			echKeys = echKeys[:5]
		}
		if err := commit(true, nil); err != nil {
			return err
		}
		p.logErrorF("INF ECH ConfigList updated")
		changed = true
	}
	p.echKeys = make([]tls.EncryptedClientHelloKey, 0, len(echKeys))
	for i, k := range echKeys {
		p.echKeys = append(p.echKeys, tls.EncryptedClientHelloKey{
			Config:      k.Config,
			PrivateKey:  k.PrivateKey,
			SendAsRetry: i == 0,
		})
	}
	p.echLastUpdate = echKeys[0].CreationTime
	configList, err := ech.ConfigList([]ech.Config{p.echKeys[0].Config})
	if err != nil {
		return err
	}
	if (changed || forceCheck) && len(p.cfg.ECH.Cloudflare) > 0 {
		ctx := p.ctx
		cf := p.cfg.ECH.Cloudflare
		go func() {
			if ctx == nil {
				ctx = context.Background()
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			targets := make(map[string][]publish.Target)
			for _, z := range cf {
				t := targets[z.Token]
				for _, name := range z.Names {
					t = append(t, publish.Target{Zone: z.Zone, Name: name})
				}
				targets[z.Token] = t
			}
			for tok, tar := range targets {
				for i, result := range p.echPublishers[tok].PublishECH(ctx, tar, configList) {
					if i >= len(tar) {
						p.logErrorF("ERR cloudflare more results than targets: %d >= %d", i, len(tar))
						continue
					}
					if err := result.Err(); err != nil {
						p.logErrorF("ERR cloudflare [%s] %s: %v", tar[i].Zone, tar[i].Name, err)
						continue
					}
					if result.Code != publish.StatusNoChange {
						p.logErrorF("INF cloudflare [%s] %s: %s", tar[i].Zone, tar[i].Name, result)
					}
				}
			}
		}()
	}
	if changed {
		if p.quicListener != nil {
			p.startQUICListener(p.ctx)
		}
		ctx := p.ctx
		webhooks := p.cfg.ECH.WebHooks
		go func() {
			if ctx == nil {
				ctx = context.Background()
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			client := retryablehttp.NewClient()
			client.Logger = nil
			for _, wh := range webhooks {
				req, err := retryablehttp.NewRequestWithContext(ctx, "POST", wh, nil)
				if err != nil {
					p.logErrorF("ERR ECH WebHook %q: %v", wh, err)
					continue
				}
				resp, err := client.Do(req)
				if err != nil {
					p.logErrorF("ERR ECH WebHook %q: %v", wh, err)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					p.logErrorF("ERR ECH WebHook %q: status code %d", wh, resp.StatusCode)
				}
			}
		}()
	}
	return nil
}

func (p *Proxy) serveECHConfigList(w http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	lastUpdate := p.echLastUpdate
	var config []byte
	if len(p.echKeys) > 0 {
		config = p.echKeys[0].Config
	}
	cacheTime := 6 * time.Hour
	if p.cfg.ECH != nil && p.cfg.ECH.Interval > 0 {
		cacheTime = min(cacheTime, p.cfg.ECH.Interval)
	}
	p.mu.Unlock()

	if config == nil {
		http.NotFound(w, req)
		return
	}
	configList, err := ech.ConfigList([]ech.Config{config})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(cacheTime.Seconds())))
	http.ServeContent(w, req, "echConfigList", lastUpdate, strings.NewReader(base64.StdEncoding.EncodeToString(configList)))
}
