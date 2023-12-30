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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const (
	hstsHeader = "Strict-Transport-Security"
	hstsValue  = "max-age=2592000" // 30 days

	viaHeader           = "Via"
	hostHeader          = "Host"
	xForwardedForHeader = "X-Forwarded-For"
)

type ctxURLKeyType int

var (
	ctxURLKey        ctxURLKeyType = 1
	ctxOverrideIDKey ctxURLKeyType = 2

	commaRE = regexp.MustCompile(`, *`)
)

// localHandler returns an HTTP handler for backends that are served entirely by
// the proxy itself. The requests are never forwarded to a remote server.
func (be *Backend) localHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC: %#v\n%s", r, string(debug.Stack()))
			}
		}()
		if !be.authenticateUser(w, &req) {
			return
		}
		if !be.handleLocalEndpointsAndAuthorize(w, req) {
			return
		}
		log.Printf("PRX %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL, http.StatusNotFound, userAgent(req))
		http.NotFound(w, req)
	})
}

// reverseProxy returns an HTTP handler for backends that act as a reverse
// proxy for remote servers. This handler can also serve local endpoints.
func (be *Backend) reverseProxy() http.Handler {
	if len(be.Addresses) == 0 {
		return be.localHandler()
	}
	reverseProxy := &httputil.ReverseProxy{
		Director:       be.reverseProxyDirector,
		Transport:      be.reverseProxyTransport(),
		ModifyResponse: be.reverseProxyModifyResponse,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC: %#v\n%s", r, string(debug.Stack()))
			}
		}()
		if !be.authenticateUser(w, &req) {
			return
		}
		if !be.handleLocalEndpointsAndAuthorize(w, req) {
			return
		}

		// Verify that the HTTP request is directed at a server names
		// that's configured for this backend. This prevents clients
		// from using one servername in the TLS handshake, and then
		// a different servername in the request.
		ctx := req.Context()
		host := req.Host
		if host == "" {
			host = connServerName(ctx.Value(connCtxKey).(net.Conn))
		}
		req.URL.Scheme = "https"
		if be.Mode == ModeHTTP {
			req.URL.Scheme = "http"
		}
		req.URL.Host = host
		req.Header.Set(hostHeader, host)
		hostname := req.URL.Hostname()

		if !slices.Contains(be.ServerNames, hostname) {
			if req.Body != nil {
				req.Body.Close()
			}
			http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
			return
		}
		ctx = context.WithValue(ctx, ctxURLKey, req.URL.String())

		// Detect forwarding loops using the via headers.
		me := req.Context().Value(connCtxKey).(net.Conn).LocalAddr().String()
		hops := commaRE.Split(req.Header.Get(viaHeader), -1)
		for _, via := range hops[:len(hops)-1] {
			_, via, _ = strings.Cut(via, " ")
			if via != me {
				continue
			}
			if req.Body != nil {
				req.Body.Close()
			}
			http.Error(w, req.Header.Get(viaHeader), http.StatusLoopDetected)
			return
		}
		hops = append(hops, req.Proto+" "+me)
		req.Header.Set(viaHeader, strings.Join(hops, ", "))

		// Apply path overrides that may direct the request to a
		// different address. The actual override will be applied in
		// dial(), but we need to set req.URL.Host to a unique value
		// so that the http client will not re-use connections with
		// other addresses.
		h := sha256.Sum256([]byte(hostname))
		hh := hex.EncodeToString(h[:])
		req.URL.Host = hh
	L:
		for i, po := range be.PathOverrides {
			for _, prefix := range po.Paths {
				if !strings.HasPrefix(req.URL.Path, prefix) {
					continue
				}
				req.URL.Host = fmt.Sprintf("%s-%d", hh, i)
				ctx = context.WithValue(ctx, ctxOverrideIDKey, i)
				break L
			}
		}

		reverseProxy.ServeHTTP(w, req.WithContext(ctx))
	})
}

func (be *Backend) setAltSvc(header http.Header, req *http.Request) {
	if be.http3Handler == nil {
		return
	}
	if req.TLS != nil && req.TLS.NegotiatedProtocol == "h3" {
		return
	}
	if be.ALPNProtos == nil || !slices.Contains(*be.ALPNProtos, "h3") {
		return
	}
	_, port, _ := net.SplitHostPort(req.Host)
	if port == "" {
		port = "443"
	}
	if p, err := strconv.Atoi(port); err == nil && p > 0 && p < 65536 {
		header.Set("Alt-Svc", fmt.Sprintf("h3=\":%d\"; ma=2592000;", p))
	}
}

// handleLocalEndpointsAndAuthorize handles local endpoints and applies the SSO
// authorization policy. It returns true if processing of the request should
// continue.
func (be *Backend) handleLocalEndpointsAndAuthorize(w http.ResponseWriter, req *http.Request) bool {
	reqHost := hostFromReq(req)
	reqPath := req.URL.Path
	hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
		if h.host != "" && h.host != reqHost {
			return false
		}
		return h.path == reqPath || (h.matchPrefix && strings.HasPrefix(reqPath, h.path+"/"))
	})
	if hi >= 0 && be.localHandlers[hi].ssoBypass {
		be.setAltSvc(w.Header(), req)
		be.localHandlers[hi].handler.ServeHTTP(w, req)
		return false
	}
	if !be.enforceSSOPolicy(w, req) {
		return false
	}
	if hi >= 0 && !be.localHandlers[hi].ssoBypass {
		be.setAltSvc(w.Header(), req)
		be.localHandlers[hi].handler.ServeHTTP(w, req)
		return false
	}
	if hi < 0 {
		pathSlash := reqPath + "/"
		if hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
			if h.host != "" && h.host != reqHost {
				return false
			}
			return pathSlash == h.path
		}); hi >= 0 {
			http.Redirect(w, req, pathSlash, http.StatusMovedPermanently)
			return false
		}
	}
	return true
}

func (be *Backend) reverseProxyDirector(req *http.Request) {
	req.Header.Del(xForwardedForHeader)
	req.Header.Del(xFCCHeader)
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 && be.ClientAuth != nil && len(be.ClientAuth.AddClientCertHeader) > 0 {
		addXFCCHeader(req, be.ClientAuth.AddClientCertHeader)
	}
}

type funcRoundTripper func(req *http.Request) (*http.Response, error)

func (rt funcRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

func (be *Backend) reverseProxyTransport() http.RoundTripper {
	h1 := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return be.dial(ctx)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return be.dial(ctx)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	h2 := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return be.dial(ctx, "h2")
		},
		DisableCompression: true,
		AllowHTTP:          true,
		ReadIdleTimeout:    30 * time.Second,
		WriteByteTimeout:   30 * time.Second,
		CountError: func(errType string) {
			be.recordEvent("http2 client error: " + errType)
		},
	}
	h3 := be.http3Transport()

	return funcRoundTripper(func(req *http.Request) (*http.Response, error) {
		proto := "http/1.1"
		if id, ok := req.Context().Value(ctxOverrideIDKey).(int); ok && id >= 0 && id < len(be.PathOverrides) && be.PathOverrides[id].BackendProto != nil {
			proto = *be.PathOverrides[id].BackendProto
		} else if be.BackendProto != nil {
			proto = *be.BackendProto
		}
		if proto == "" && req.TLS != nil && req.TLS.NegotiatedProtocol != "" {
			proto = req.TLS.NegotiatedProtocol
		}
		if proto == "h3" && h3 != nil {
			return h3.RoundTrip(req)
		}
		if proto == "h2" {
			return h2.RoundTrip(req)
		}
		return h1.RoundTrip(req)
	})
}

func (be *Backend) reverseProxyModifyResponse(resp *http.Response) error {
	req := resp.Request
	var cl string
	if resp.ContentLength != -1 {
		cl = fmt.Sprintf(" content-length:%d", resp.ContentLength)
	}
	url, _ := req.Context().Value(ctxURLKey).(string)
	log.Printf("PRX %s ➔ %s %s ➔ status:%d%s (%q)", formatReqDesc(req), req.Method, url, resp.StatusCode, cl, userAgent(req))

	if resp.StatusCode != http.StatusMisdirectedRequest && resp.Header.Get(hstsHeader) == "" {
		resp.Header.Set(hstsHeader, hstsValue)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 && resp.Header.Get("Alt-Svc") == "" {
		be.setAltSvc(resp.Header, req)
	}
	return nil
}
