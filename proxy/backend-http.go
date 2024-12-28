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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
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

func (be *Backend) logPanic(req *http.Request, recovered any) {
	if recovered == http.ErrAbortHandler {
		be.logErrorF("ERR %s ➔ %s %s ➔ Aborted (%q)", formatReqDesc(req), req.Method, req.URL, userAgent(req))
		return
	}
	be.logErrorF("PANIC: %#v\n%s", recovered, string(debug.Stack()))
}

// localHandler returns an HTTP handler for backends that are served entirely by
// the proxy itself. The requests are never forwarded to a remote server.
func (be *Backend) localHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				be.logPanic(req, r)
			}
		}()
		if !be.authenticateUser(w, &req) {
			return
		}
		if !be.handleLocalEndpointsAndAuthorize(w, req) {
			return
		}
		be.serveStaticFiles(w, req, be.documentRoot, "")
	})
}

func (be *Backend) redirectPermanently(w http.ResponseWriter, req *http.Request, path string) {
	code := http.StatusMovedPermanently
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		code = http.StatusSeeOther
	}
	u := url.URL{
		Path:     path,
		RawQuery: req.URL.RawQuery,
	}
	be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL.Path, code, userAgent(req))
	http.Redirect(w, req, u.String(), code)
}

func pathClean(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	pp := path.Clean(p)
	if pp == "." {
		pp = "/"
	}
	if pp != "/" && strings.HasSuffix(p, "/") {
		pp += "/"
	}
	return pp
}

func (be *Backend) serveStaticFiles(w http.ResponseWriter, req *http.Request, docRoot *os.Root, prefix string) {
	notFound := func() {
		be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL, http.StatusNotFound, userAgent(req))
		http.NotFound(w, req)
	}

	if docRoot == nil {
		notFound()
		return
	}

	switch req.Method {
	case http.MethodGet, http.MethodHead:
	default:
		be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL.Path, http.StatusMethodNotAllowed, userAgent(req))
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	cleanPath := pathClean(req.URL.Path)
	if cleanPath != req.URL.Path {
		be.redirectPermanently(w, req, cleanPath)
		return
	}
	p := strings.TrimPrefix(cleanPath, prefix)
	p = strings.TrimPrefix(p, "/")
	for _, pp := range strings.Split(p, "/") {
		if strings.HasPrefix(pp, ".") || strings.Contains(pp, `\`) {
			notFound()
			return
		}
	}
	p = filepath.Join(".", filepath.FromSlash(p))
	fi, err := docRoot.Stat(p)
	if err != nil {
		notFound()
		return
	}
	if fi.IsDir() {
		if !strings.HasSuffix(cleanPath, "/") {
			be.redirectPermanently(w, req, cleanPath+"/")
			return
		}
		p = filepath.Join(p, "index.html")
		if s, err := docRoot.Stat(p); err != nil || s.IsDir() {
			be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL.Path, http.StatusForbidden, userAgent(req))
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else if strings.HasSuffix(cleanPath, "/") {
		be.redirectPermanently(w, req, strings.TrimSuffix(cleanPath, "/"))
		return
	}
	f, err := docRoot.Open(p)
	if err != nil {
		notFound()
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL.Path, http.StatusForbidden, userAgent(req))
		w.WriteHeader(http.StatusForbidden)
		return
	}
	be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL.Path, http.StatusOK, userAgent(req))
	be.setAltSvc(w.Header(), req)
	http.ServeContent(w, req, p, fi.ModTime(), f)
}

// reverseProxy returns an HTTP handler for backends that act as a reverse
// proxy for remote servers. This handler can also serve local endpoints.
func (be *Backend) reverseProxy() http.Handler {
	reverseProxy := &httputil.ReverseProxy{
		Director:       be.reverseProxyDirector,
		Transport:      be.reverseProxyTransport(),
		ModifyResponse: be.reverseProxyModifyResponse,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				be.logPanic(req, r)
			}
		}()
		if !be.authenticateUser(w, &req) {
			return
		}
		if !be.handleLocalEndpointsAndAuthorize(w, req) {
			return
		}

		// Verify that the HTTP request is directed at a server name
		// that's configured for this backend. This prevents clients
		// from using one server name in the TLS handshake, and then
		// a different server name in the request.
		ctx := req.Context()
		serverName := connServerName(ctx.Value(connCtxKey).(anyConn))
		host := req.Host
		if host == "" {
			host = serverName
		}
		req.URL.Host = host
		req.Header.Set(hostHeader, host)

		req.URL.Scheme = "https"
		if be.Mode == ModeHTTP {
			req.URL.Scheme = "http"
		}

		if !slices.Contains(be.ServerNames, req.URL.Hostname()) {
			if req.Body != nil {
				req.Body.Close()
			}
			http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
			return
		}
		ctx = context.WithValue(ctx, ctxURLKey, req.URL.String())

		// Apply the forward rate limit. The first request was already
		// counted when the connection was established.
		if conn, ok := ctx.Value(connCtxKey).(annotatedConnection); ok {
			if !conn.Annotation(requestFlagKey, false).(bool) {
				conn.SetAnnotation(requestFlagKey, true)
			} else if err := be.connLimit.Wait(ctx); err != nil {
				http.Error(w, "ctx", http.StatusInternalServerError)
				return
			}
		}

		// Apply path overrides that may direct the request to a
		// different address. The actual override will be applied in
		// dial(), but we need to set req.URL.Host to a unique value
		// so that the http client will not re-use connections with
		// other addresses.
		override := ""
		proxyProtoVersion := be.proxyProtocolVersion
		httpHeaders := be.ForwardHTTPHeaders
		cleanPath := pathClean(req.URL.Path)
		sanitizePath := be.SanitizePath == nil || *be.SanitizePath
	L:
		for i, po := range be.PathOverrides {
			for _, prefix := range po.Paths {
				if cleanPath+"/" == prefix {
					be.redirectPermanently(w, req, cleanPath+"/")
					return
				}
				if !strings.HasPrefix(cleanPath, prefix) {
					continue
				}
				if len(po.Addresses) == 0 {
					be.serveStaticFiles(w, req, po.documentRoot, prefix)
					return
				}
				if po.SanitizePath != nil {
					sanitizePath = *po.SanitizePath
				}
				if po.ForwardHTTPHeaders != nil {
					httpHeaders = *po.ForwardHTTPHeaders
				}
				ctx = context.WithValue(ctx, ctxOverrideIDKey, i)
				override = fmt.Sprintf("%d", i)
				proxyProtoVersion = po.proxyProtocolVersion
				break L
			}
		}
		if len(be.Addresses) == 0 {
			be.serveStaticFiles(w, req, be.documentRoot, "")
			return
		}

		hostKey := bytes.NewBufferString(serverName + ";" + override)
		if proxyProtoVersion > 0 {
			hostKey.WriteByte(';')
			writeProxyHeader(proxyProtoVersion, hostKey, req.Context().Value(connCtxKey).(anyConn))
		}
		h := sha256.Sum256(hostKey.Bytes())
		req.URL.Host = hex.EncodeToString(h[:])

		// Detect forwarding loops using the via headers.
		me := localNetConn(req.Context().Value(connCtxKey).(anyConn)).LocalAddr().String()
		var hops []string
		if h := req.Header.Get(viaHeader); h != "" {
			hops = commaRE.Split(h, -1)
		}
		for _, via := range hops {
			if _, via, _ = strings.Cut(via, " "); via == me {
				if req.Body != nil {
					req.Body.Close()
				}
				http.Error(w, req.Header.Get(viaHeader), http.StatusLoopDetected)
				return
			}
		}
		hops = append(hops, req.Proto+" "+me)
		req.Header.Set(viaHeader, strings.Join(hops, ", "))

		if sanitizePath {
			req.URL.Path = cleanPath
		}
		for k, v := range httpHeaders {
			v = expandVars(v, req)
			if v != "" {
				req.Header.Set(k, v)
				if strings.ToLower(k) == strings.ToLower(hostHeader) {
					req.Host = v
				}
			} else {
				req.Header.Del(k)
			}
		}
		// A value of -1 for ContentLength indicates that the size of
		// request's body is unknown or that the client did not specify
		// it.
		//
		// The http2.Transport code encodes the request differently
		// when the content length is unknown, i.e. it doesn't set the
		// END_STREAM flag after the headers are sent, even for GET
		// requests. This is flagged as a protocol violation by some
		// HTTP servers, lighttpd in particular.
		//
		// To improve compatibility, we explicitly set the value to 0
		// the HTTP methods don't expect a body and the client didn't
		// provide a content length.
		if req.ContentLength < 0 && req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodPatch {
			req.ContentLength = 0
		}
		if req.ContentLength == 0 && req.Body != nil {
			req.Body.Close()
			req.Body = nil
		}
		reverseProxy.ServeHTTP(w, req.WithContext(ctx))
	})
}

func addr2ip(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		return ""
	}
}

func expandVars(s string, req *http.Request) string {
	ctx := req.Context()
	claims := claimsFromCtx(ctx)
	conn := ctx.Value(connCtxKey).(anyConn)
	return os.Expand(s, func(n string) string {
		switch n {
		case "NETWORK":
			return conn.LocalAddr().Network()
		case "LOCAL_ADDR":
			return conn.LocalAddr().String()
		case "REMOTE_ADDR":
			return conn.RemoteAddr().String()
		case "LOCAL_IP":
			return addr2ip(conn.LocalAddr())
		case "REMOTE_IP":
			return addr2ip(conn.RemoteAddr())
		case "SERVER_NAME":
			return idnaToUnicode(connServerName(conn))
		default:
			if strings.HasPrefix(n, "JWT:") {
				if v, exists := claims[n[4:]]; exists {
					return fmt.Sprint(v)
				}
			}
			return ""
		}
	})
}

func (be *Backend) setAltSvc(header http.Header, req *http.Request) {
	if be.http3Server == nil {
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
	cleanPath := pathClean(req.URL.Path)
	hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
		if h.host != "" && h.host != reqHost {
			return false
		}
		return h.path == cleanPath || (h.matchPrefix && strings.HasPrefix(cleanPath, h.path+"/"))
	})
	if hi >= 0 {
		if !be.localHandlers[hi].ssoBypass && !be.enforceSSOPolicy(w, req) {
			return false
		}
		if cleanPath != req.URL.Path {
			be.redirectPermanently(w, req, cleanPath)
			return false
		}
		be.setAltSvc(w.Header(), req)
		be.localHandlers[hi].handler.ServeHTTP(w, req)
		return false
	}
	if !be.enforceSSOPolicy(w, req) {
		return false
	}
	if hi < 0 {
		pathSlash := cleanPath + "/"
		if hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
			if h.host != "" && h.host != reqHost {
				return false
			}
			return pathSlash == h.path
		}); hi >= 0 {
			be.redirectPermanently(w, req, pathSlash)
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
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	h2 := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return be.dial(ctx, "h2")
		},
		DisableCompression: true,
		AllowHTTP:          true,
		ReadIdleTimeout:    10 * time.Second,
		WriteByteTimeout:   30 * time.Second,
		CountError: func(errType string) {
			be.recordEvent("http2 client error: " + errType)
		},
	}
	h3 := be.http3Transport()

	return funcRoundTripper(func(req *http.Request) (*http.Response, error) {
		// Connection upgrades, e.g. websocket, must use http/1.
		if req.ProtoMajor == 1 && strings.ToLower(req.Header.Get("connection")) == "upgrade" {
			return h1.RoundTrip(req)
		}

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
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if c, ok := req.Context().Value(connCtxKey).(anyConn); ok {
			annotatedConn(c).SetAnnotation(httpUpgradeKey, resp.Header.Get("upgrade"))
		}
	}
	var cl string
	if resp.ContentLength != -1 {
		cl = fmt.Sprintf(" content-length:%d", resp.ContentLength)
	}
	url, _ := req.Context().Value(ctxURLKey).(string)
	be.logRequestF("PRX %s ➔ %s %s ➔ status:%d%s (%q)", formatReqDesc(req), req.Method, url, resp.StatusCode, cl, userAgent(req))

	if resp.StatusCode != http.StatusMisdirectedRequest && resp.Header.Get(hstsHeader) == "" {
		resp.Header.Set(hstsHeader, hstsValue)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 && resp.Header.Get("Alt-Svc") == "" {
		be.setAltSvc(resp.Header, req)
	}
	return nil
}
