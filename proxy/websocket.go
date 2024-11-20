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
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

func newWebSocketUpgrader() *websocket.Upgrader {
	return &websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
	}
}

func (p *Proxy) webSocketHandler(cfg WebSocketConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		in, err := p.wsUpgrader.Upgrade(w, req, nil)
		if err != nil {
			p.logErrorF("ERR %v", err)
			return
		}
		defer in.Close()

		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		out, err := dialer.DialContext(req.Context(), "tcp", cfg.Address)
		if err != nil {
			p.logErrorF("ERR webSocketHandler: %v", err)
			return
		}

		done := make(chan bool, 2)

		lastActive := time.Now()
		in.SetPongHandler(func(string) error {
			lastActive = time.Now()
			return nil
		})
		go func() {
			ctx := req.Context()
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if time.Since(lastActive) > 30*time.Second {
						done <- true
						return
					}
					if err := in.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second)); err != nil {
						p.logErrorF("ERR WriteControl: %v", err)
					}
				}
			}
		}()

		// in -> out loop
		go func() {
			defer func() {
				done <- true
			}()
			for {
				messageType, r, err := in.NextReader()
				if err != nil {
					return
				}
				if messageType != websocket.BinaryMessage {
					continue
				}
				if _, err := io.Copy(out, r); err != nil {
					return
				}
			}
		}()

		// out -> in loop
		go func() {
			defer func() {
				done <- true
			}()
			buf := make([]byte, 1024)
			for {
				n, err := out.Read(buf)
				if n > 0 {
					if err := in.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()

		<-done
	})
}
