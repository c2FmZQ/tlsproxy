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

// Enable HTTP/2 Extended CONNECT (RFC 8441) via GODEBUG=http2xconnect=1 before
// net/http initializes (needed until Go 1.28's HTTP2Config.EnableConnectProtocol).
import _ "github.com/c2FmZQ/websocket/h2xconnect"

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/csrf"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/sid"
)

const (
	hstsHeader = "Strict-Transport-Security"
	hstsValue  = "max-age=2592000" // 30 days

	viaHeader             = "Via"
	hostHeader            = "Host"
	xForwardedForHeader   = "X-Forwarded-For"
	xForwardedHostHeader  = "X-Forwarded-Host"
	xForwardedProtoHeader = "X-Forwarded-Proto"
	forwardedHeader       = "Forwarded"
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
		panic(http.ErrAbortHandler)
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
		if !be.checkRequestHost(w, req) {
			return
		}
		if !be.checkConnectRequest(w, req) {
			return
		}
		if !be.authenticateUser(w, &req) {
			return
		}
		if !be.handleLocalEndpointsAndAuthorize(w, req) {
			return
		}
		be.serveStaticFiles(w, req, be.documentRoot, "")
	})
}

// checkRequestHost verifies that the HTTP request is directed at a server name
// that's configured for this backend. This prevents clients from using one
// server name in the TLS handshake, and then a different server name in the
// request. It must be called before anything uses req.Host.
func (be *Backend) checkRequestHost(w http.ResponseWriter, req *http.Request) bool {
	if req.Host == "" {
		req.Host = connServerName(req.Context().Value(connCtxKey).(anyConn))
	}
	if !slices.Contains(be.ServerNames, hostFromReq(req)) {
		if req.Body != nil {
			req.Body.Close()
		}
		http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
		return false
	}
	if req.URL.Opaque != "" || (req.URL.Host != "" && req.URL.Host != req.Host) || (req.URL.Path != "" && !strings.HasPrefix(req.URL.Path, "/") && !(req.Method == http.MethodOptions && req.URL.Path == "*")) {
		if req.Body != nil {
			req.Body.Close()
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return false
	}
	return true
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
	transport := be.reverseProxyTransport()
	reverseProxy := &httputil.ReverseProxy{
		Director:       be.reverseProxyDirector,
		Transport:      transport,
		ModifyResponse: be.reverseProxyModifyResponse,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				be.logPanic(req, r)
			}
		}()
		// Remove the hop-by-hop headers listed in the client's Connection
		// header before the proxy injects any header of its own, so that
		// clients can't use it to strip proxy-injected headers.
		cleanConnectionHeaders(req.Header)
		if !be.checkRequestHost(w, req) {
			return
		}
		if !be.checkConnectRequest(w, req) {
			return
		}
		if !be.authenticateUser(w, &req) {
			return
		}
		if !be.handleLocalEndpointsAndAuthorize(w, req) {
			return
		}

		ctx := req.Context()
		serverName := connServerName(ctx.Value(connCtxKey).(anyConn))
		req.URL.Host = req.Host
		req.Header.Set(hostHeader, req.Host)

		req.URL.Scheme = "https"
		if be.Mode == ModeHTTP {
			req.URL.Scheme = "http"
		}
		ctx = context.WithValue(ctx, ctxURLKey, req.URL.String())

		// Apply the forward rate limit. The first request was already
		// counted when the connection was established.
		if ac, ok := ctx.Value(connCtxKey).(anyConn); ok {
			conn := annotatedConn(ac)
			if !conn.Annotation(requestFlagKey, false).(bool) {
				conn.SetAnnotation(requestFlagKey, true)
			} else if err := be.waitConnLimit(ctx); err != nil {
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
		for _, h := range req.Header.Values(viaHeader) {
			if h != "" {
				hops = append(hops, commaRE.Split(h, -1)...)
			}
		}
		for _, via := range hops {
			if _, via, _ = strings.Cut(via, " "); via == me {
				if req.Body != nil {
					req.Body.Close()
				}
				http.Error(w, strings.Join(req.Header.Values(viaHeader), ", "), http.StatusLoopDetected)
				return
			}
		}
		viaProto := req.Proto
		if req.ProtoMajor == 3 {
			viaProto = "HTTP/3.0"
		}
		hops = append(hops, viaProto+" "+me)
		req.Header.Set(viaHeader, strings.Join(hops, ", "))

		if sanitizePath {
			req.URL.Path = cleanPath
		}
		delHeaderVariants(req.Header, xForwardedForHeader)
		delHeaderVariants(req.Header, xFCCHeader)
		delHeaderVariants(req.Header, forwardedHeader)
		delHeaderVariants(req.Header, xForwardedHostHeader)
		delHeaderVariants(req.Header, xForwardedProtoHeader)
		req.Header.Set(xForwardedHostHeader, req.Host)
		req.Header.Set(xForwardedProtoHeader, "https")
		for k, v := range httpHeaders {
			delHeaderVariants(req.Header, k)
			v = expandVars(v, req)
			if v != "" {
				req.Header.Set(k, v)
				if strings.ToLower(k) == strings.ToLower(hostHeader) {
					req.Host = v
				}
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
		if req.ContentLength < 0 && req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodPatch && req.Method != http.MethodConnect {
			req.ContentLength = 0
		}
		if req.ContentLength == 0 && req.Body != nil {
			req.Body.Close()
			req.Body = nil
		}
		if extProto, isExt, _ := extendedConnectProtocol(req); isExt {
			be.forwardExtendedConnect(w, req.WithContext(ctx), transport, extProto)
			return
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
	claims := fromctx.Claims(ctx)
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

func (be *Backend) checkScopes(want []string, w http.ResponseWriter, req *http.Request) bool {
	if len(want) == 0 {
		return true // no restriction
	}
	claims := fromctx.Claims(req.Context())
	if claims == nil {
		http.Error(w, "missing request authorization", http.StatusForbidden)
		return false // no user identity
	}
	scope := claims["scope"]
	if scope == nil {
		return true // no restriction
	}
	if scopes, ok := scope.([]any); ok {
		if slices.ContainsFunc(want, func(w string) bool {
			return slices.Contains(scopes, any(w))
		}) {
			return true
		}
	}
	userID, _ := claims["email"].(string)
	host := connServerName(req.Context().Value(connCtxKey).(anyConn))
	be.recordEvent(fmt.Sprintf("deny SSO scope %s to %s", userID, idnaToUnicode(host)))
	be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (SCOPE) (%q)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusForbidden, userAgent(req))
	http.Error(w, "missing scope: "+strings.Join(want, ","), http.StatusForbidden)
	return false
}

// setNoFrameHeaders prevents the response from being displayed in a frame
// (clickjacking protection).
func setNoFrameHeaders(h http.Header) {
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
}

// handleLocalEndpointsAndAuthorize handles local endpoints and applies the SSO
// authorization policy. It returns true if processing of the request should
// continue.
func (be *Backend) handleLocalEndpointsAndAuthorize(w http.ResponseWriter, req *http.Request) bool {
	defer func() {
		// Filter out the tlsproxy auth and session cookies.
		cookiemanager.FilterOutAuthTokenCookie(req)
		sid.FilterOutSessionCookie(req)
	}()

	reqHost := hostFromReq(req)
	cleanPath := pathClean(req.URL.Path)
	hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
		if h.host != "" && h.host != reqHost {
			return false
		}
		return h.path == cleanPath || (h.matchPrefix && strings.HasPrefix(cleanPath, h.path+"/"))
	})
	if hi >= 0 {
		if !be.localHandlers[hi].csrfBypass && !csrf.Check(w, req) {
			return false
		}
		if be.localHandlers[hi].ssoBypass && !be.checkScopes(be.localHandlers[hi].scopes, w, req) {
			return false
		}
		if !be.localHandlers[hi].ssoBypass && !be.enforceSSOPolicy(w, req, be.localHandlers[hi].scopes) {
			return false
		}
		if cleanPath != req.URL.Path {
			be.redirectPermanently(w, req, cleanPath)
			return false
		}
		setNoFrameHeaders(w.Header())
		be.setAltSvc(w.Header(), req)
		if !be.localHandlers[hi].noBodyLimit {
			// Set a sensible limit for local handlers.
			req.Body = http.MaxBytesReader(w, req.Body, 102400)
		}
		be.localHandlers[hi].handler.ServeHTTP(w, req)
		return false
	}
	if !be.enforceSSOPolicy(w, req, nil) {
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
	if be.ClientAuth != nil && len(be.ClientAuth.AddClientCertHeader) > 0 {
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
		if req.ProtoMajor == 1 && isConnectionUpgrade(req.Header) {
			return h1.RoundTrip(req)
		}

		proto := be.backendProto(req)
		if proto == "h3" && h3 != nil {
			return h3.RoundTrip(req)
		}
		if proto == "h2" {
			return h2.RoundTrip(req)
		}
		return h1.RoundTrip(req)
	})
}

type eofSignalReader struct {
	r    io.Reader
	once sync.Once
	done chan struct{}
}

func newEOFSignalReader(r io.Reader) *eofSignalReader {
	done := make(chan struct{})
	if r == nil {
		close(done)
		return &eofSignalReader{r: http.NoBody, done: done}
	}
	return &eofSignalReader{r: r, done: done}
}

func (e *eofSignalReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil {
		e.once.Do(func() { close(e.done) })
	}
	return n, err
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"HTTP2-Settings",
}

func removeHopByHopHeaders(h http.Header, preserveTETrailers bool) {
	cleanConnectionHeaders(h)
	teTrailers := preserveTETrailers && headerContainsToken(h, "Te", "trailers")
	for _, k := range hopByHopHeaders {
		delHeaderVariants(h, k)
	}
	if teTrailers {
		h.Set("Te", "trailers")
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func headerContainsToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), token) {
				return true
			}
		}
	}
	return false
}

func computeWebSocketAccept(challengeKey string) string {
	const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(challengeKey))
	h.Write([]byte(wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func isH2TransportProtocolHeaderUnsupported(err error) bool {
	// In Go 1.27 (without -tags http2legacy), net/http.Transport rejects the
	// ":protocol" header on outbound HTTP/2 requests (go.dev/issue/53208).
	return err != nil && strings.Contains(err.Error(), `invalid header field name ":protocol"`)
}

func isExtendedConnectUnsupportedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "extended connect not supported") ||
		strings.Contains(msg, "didn't enable Extended CONNECT") ||
		isH2TransportProtocolHeaderUnsupported(err)
}

func (be *Backend) halfCloseParams() (serverClose, clientClose bool, timeout time.Duration) {
	serverClose = true
	if be.ServerCloseEndsConnection != nil {
		serverClose = *be.ServerCloseEndsConnection
	}
	clientClose = false
	if be.ClientCloseEndsConnection != nil {
		clientClose = *be.ClientCloseEndsConnection
	}
	timeout = time.Minute
	if be.HalfCloseTimeout != nil {
		timeout = *be.HalfCloseTimeout
	}
	return serverClose, clientClose, timeout
}

func prepareExtendedConnectHeaders(req *http.Request) {
	removeHopByHopHeaders(req.Header, true)
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior := req.Header.Values(xForwardedForHeader); len(prior) > 0 {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set(xForwardedForHeader, clientIP)
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}
}

func (be *Backend) forwardExtendedConnect(w http.ResponseWriter, req *http.Request, transport http.RoundTripper, extProto string) {
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	origBody := req.Body
	if origBody != nil {
		defer origBody.Close()
	}

	req = req.WithContext(ctx)
	prepareExtendedConnectHeaders(req)

	isWS := strings.EqualFold(extProto, "websocket")
	beProto := be.backendProto(req)
	if beProto == "h3" && !quicIsEnabled {
		beProto = "http/1.1"
	}

	if beProto != "h2" && beProto != "h3" {
		if isWS {
			be.forwardWebSocketViaH1(w, req, origBody, transport)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}

	outReq := req.Clone(ctx)
	eofBody := newEOFSignalReader(origBody)
	// Protect origBody from being closed by transport.RoundTrip if the peer
	// rejects Extended CONNECT before sending headers, allowing fallback to
	// HTTP/1.1 WebSocket upgrade.
	outReq.Body = io.NopCloser(eofBody)
	if beProto == "h2" {
		outReq.Header.Set(":protocol", extProto)
	} else {
		outReq.Proto = extProto
		outReq.Header.Del(":protocol")
	}

	be.reverseProxyDirector(outReq)
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		if isWS && isExtendedConnectUnsupportedErr(err) {
			be.forwardWebSocketViaH1(w, req, origBody, transport)
			return
		}
		if isH2TransportProtocolHeaderUnsupported(err) {
			http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
			return
		}
		be.logErrorF("ERR Extended CONNECT: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header, false)
	if err := be.reverseProxyModifyResponse(resp); err != nil {
		be.logErrorF("ERR Extended CONNECT ModifyResponse: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	serverClose, _, halfCloseTimeout := be.halfCloseParams()
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			if err == io.EOF {
				if !serverClose && resp.StatusCode == http.StatusOK {
					select {
					case <-eofBody.done:
					case <-ctx.Done():
					case <-time.After(halfCloseTimeout):
					}
				}
				return
			}
			be.logErrorF("ERR Extended CONNECT copy: %v", err)
			panic(http.ErrAbortHandler)
		}
	}
}

// forwardWebSocketViaH1 translates an incoming HTTP/2 (RFC 8441) or HTTP/3
// (RFC 9220) Extended CONNECT WebSocket request into an outbound HTTP/1.1
// GET + Upgrade: websocket handshake, and bridges the raw RFC 6455 frame
// streams upon receiving 101 Switching Protocols.
func (be *Backend) forwardWebSocketViaH1(w http.ResponseWriter, req *http.Request, origBody io.ReadCloser, transport http.RoundTripper) {
	ctx := req.Context()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		be.logErrorF("ERR forwardWebSocketViaH1 rand: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	wsKey := base64.StdEncoding.EncodeToString(nonce[:])

	h1Req := req.Clone(ctx)
	h1Req.Method = http.MethodGet
	h1Req.Proto = "HTTP/1.1"
	h1Req.ProtoMajor = 1
	h1Req.ProtoMinor = 1
	h1Req.Body = nil
	h1Req.ContentLength = 0
	h1Req.Header.Del(":protocol")
	h1Req.Header.Set("Connection", "Upgrade")
	h1Req.Header.Set("Upgrade", "websocket")
	h1Req.Header.Set("Sec-WebSocket-Key", wsKey)
	if h1Req.Header.Get("Sec-WebSocket-Version") == "" {
		h1Req.Header.Set("Sec-WebSocket-Version", "13")
	}

	be.reverseProxyDirector(h1Req)
	resp, err := transport.RoundTrip(h1Req)
	if err != nil {
		be.logErrorF("ERR Extended CONNECT->H1 WebSocket: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if err := be.reverseProxyModifyResponse(resp); err != nil {
		be.logErrorF("ERR Extended CONNECT->H1 ModifyResponse: %v", err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		removeHopByHopHeaders(resp.Header, false)
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			be.logErrorF("ERR Extended CONNECT->H1 error body copy: %v", err)
			panic(http.ErrAbortHandler)
		}
		return
	}

	backConn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok ||
		!headerContainsToken(resp.Header, "Upgrade", "websocket") ||
		!headerContainsToken(resp.Header, "Connection", "upgrade") ||
		resp.Header.Get("Sec-WebSocket-Accept") != computeWebSocketAccept(wsKey) {
		be.logErrorF("ERR Extended CONNECT->H1 invalid 101 handshake response from backend")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	removeHopByHopHeaders(resp.Header, false)
	delHeaderVariants(resp.Header, "Sec-WebSocket-Accept")
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	serverClose, clientClose, halfCloseTimeout := be.halfCloseParams()
	var closing atomic.Bool
	closeBack := func() {
		closing.Store(true)
		_ = backConn.Close()
	}

	var inReader io.Reader = http.NoBody
	if origBody != nil {
		inReader = origBody
	}

	reqDone := make(chan struct{})
	var hcTimerMu sync.Mutex
	var hcTimer *time.Timer
	stopHCTimer := func() {
		hcTimerMu.Lock()
		if hcTimer != nil {
			hcTimer.Stop()
		}
		hcTimerMu.Unlock()
	}
	defer stopHCTimer()

	go func() {
		defer close(reqDone)
		_, copyErr := io.Copy(backConn, inReader)
		if copyErr != nil || clientClose {
			closeBack()
			return
		}
		if cw, ok := backConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		hcTimerMu.Lock()
		if !closing.Load() {
			hcTimer = time.AfterFunc(halfCloseTimeout, closeBack)
		}
		hcTimerMu.Unlock()
	}()

	stopOnCtx := context.AfterFunc(ctx, closeBack)
	defer stopOnCtx()

	buf := make([]byte, 32*1024)
	var backendReadErr error
	for {
		n, rerr := backConn.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				closeBack()
				if origBody != nil {
					_ = origBody.Close()
				}
				<-reqDone
				return
			}
			_ = rc.Flush()
		}
		if rerr != nil {
			if rerr != io.EOF && !closing.Load() {
				backendReadErr = rerr
			}
			break
		}
	}

	if backendReadErr == nil && !serverClose {
		select {
		case <-reqDone:
		case <-ctx.Done():
		case <-time.After(halfCloseTimeout):
		}
	}

	closeBack()
	if origBody != nil {
		_ = origBody.Close()
	}
	<-reqDone

	if backendReadErr != nil {
		be.logErrorF("ERR Extended CONNECT->H1 copy: %v", backendReadErr)
		panic(http.ErrAbortHandler)
	}
}

func (be *Backend) backendProto(req *http.Request) string {
	proto := "http/1.1"
	if id, ok := req.Context().Value(ctxOverrideIDKey).(int); ok && id >= 0 && id < len(be.PathOverrides) && be.PathOverrides[id].BackendProto != nil {
		proto = *be.PathOverrides[id].BackendProto
	} else if be.BackendProto != nil {
		proto = *be.BackendProto
	}
	if proto == "" && req.TLS != nil && req.TLS.NegotiatedProtocol != "" {
		proto = req.TLS.NegotiatedProtocol
	}
	return proto
}

// extendedConnectProtocol extracts and validates the Extended CONNECT :protocol
// token (RFC 8441 / RFC 9220). It returns:
//   - isExt=false, valid=true  for non-extended requests
//   - isExt=true,  valid=false for malformed :protocol values
//   - isExt=true,  valid=true  for valid Extended CONNECT requests
func extendedConnectProtocol(req *http.Request) (proto string, isExt bool, valid bool) {
	if req.Method != http.MethodConnect {
		return "", false, true
	}
	switch req.ProtoMajor {
	case 2:
		protos, ok := req.Header[":protocol"]
		if !ok {
			return "", false, true
		}
		if len(protos) != 1 || protos[0] == "" || !httpguts.ValidHeaderFieldName(protos[0]) {
			return "", true, false
		}
		return protos[0], true, true
	case 3:
		if req.Proto == "" || req.Proto == "HTTP/3.0" {
			return "", false, true
		}
		if !httpguts.ValidHeaderFieldName(req.Proto) {
			return "", true, false
		}
		return req.Proto, true, true
	default:
		return "", false, true
	}
}

func (be *Backend) checkConnectRequest(w http.ResponseWriter, req *http.Request) bool {
	if req.Method != http.MethodConnect {
		return true
	}
	_, isExt, valid := extendedConnectProtocol(req)
	if !valid {
		if req.Body != nil {
			req.Body.Close()
		}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return false
	}
	if !isExt {
		if req.Body != nil {
			req.Body.Close()
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func isConnectionUpgrade(h http.Header) bool {
	return headerContainsToken(h, "Connection", "upgrade")
}

func (be *Backend) reverseProxyModifyResponse(resp *http.Response) error {
	req := resp.Request
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if c, ok := req.Context().Value(connCtxKey).(anyConn); ok {
			if p := connProto(c); p != "h2" && p != "h3" {
				annotatedConn(c).SetAnnotation(httpUpgradeKey, resp.Header.Get("upgrade"))
			}
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
	filterOutProxyCookies(resp.Header)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 && resp.Header.Get("Alt-Svc") == "" {
		be.setAltSvc(resp.Header, req)
	}
	return nil
}

// filterOutProxyCookies removes the Set-Cookie headers that would set the
// proxy's own cookies. Backends must not be able to set them, e.g. to log users
// into another account.
func filterOutProxyCookies(h http.Header) {
	cookies := h.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, c := range cookies {
		name, _, _ := strings.Cut(c, "=")
		name = strings.TrimSpace(name)
		if cookiemanager.IsProxyCookie(name) || sid.IsCookie(name) {
			continue
		}
		h.Add("Set-Cookie", c)
	}
}

// cleanConnectionHeaders removes client-specified hop-by-hop headers before the
// proxy adds its own headers, preventing a client Connection header from
// instructing httputil.ReverseProxy to strip proxy-injected headers.
func cleanConnectionHeaders(h http.Header) {
	connHeaders := h.Values("Connection")
	if len(connHeaders) == 0 {
		return
	}
	hasUpgrade := false
	for _, v := range connHeaders {
		for _, f := range commaRE.Split(v, -1) {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			if strings.EqualFold(f, "upgrade") && h.Get("Upgrade") != "" {
				hasUpgrade = true
				continue
			}
			delHeaderVariants(h, f)
		}
	}
	delHeaderVariants(h, "Connection")
	if hasUpgrade {
		h.Set("Connection", "upgrade")
	}
}
