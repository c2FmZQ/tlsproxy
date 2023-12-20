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
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

//go:embed c2.png
var iconBytes []byte

func (p *Proxy) recordEvent(msg string) {
	p.eventsmu.Lock()
	defer p.eventsmu.Unlock()
	if p.events == nil {
		p.events = make(map[string]int64)
	}
	p.events[msg]++
}

func (p *Proxy) addConn(c *netw.Conn) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections[connKey{c.LocalAddr(), c.RemoteAddr(), c.StreamID()}] = c
	return len(p.connections)
}

func (p *Proxy) removeConn(c *netw.Conn) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.connections, connKey{c.LocalAddr(), c.RemoteAddr(), c.StreamID()})

	if sn := c.Annotation(serverNameKey, "").(string); sn != "" && p.backends[beKey{serverName: sn}] != nil {
		if p.metrics == nil {
			p.metrics = make(map[string]*backendMetrics)
		}
		m := p.metrics[sn]
		if m == nil {
			m = &backendMetrics{}
			p.metrics[sn] = m
		}
		m.numConnections++
		m.numBytesSent += c.BytesSent()
		m.numBytesReceived += c.BytesReceived()
	}

	return len(p.connections)
}

func (p *Proxy) metricsHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	req.ParseForm()
	if v := req.Form.Get("refresh"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			w.Header().Set("refresh", strconv.Itoa(i))
		}
	}

	var buf bytes.Buffer
	defer buf.WriteTo(w)

	p.mu.Lock()
	defer p.mu.Unlock()

	totals := make(map[string]*backendMetrics)
	for k, v := range p.metrics {
		m := *v
		k = idnaToUnicode(k)
		totals[k] = &m
	}
	for _, c := range p.connections {
		sn := c.Annotation(serverNameKey, "").(string)
		if sn == "" || connBackend(c) == (*Backend)(nil) {
			continue
		}
		sn = idnaToUnicode(sn)
		m := totals[sn]
		if m == nil {
			m = &backendMetrics{}
			totals[sn] = m
		}
		m.numConnections++
		m.numBytesSent += c.BytesSent()
		m.numBytesReceived += c.BytesReceived()
	}

	var serverNames []string
	var maxLen int
	for k := range totals {
		if n := len(k); n > maxLen {
			maxLen = n
		}
		serverNames = append(serverNames, k)
	}
	sort.Strings(serverNames)
	fmt.Fprintln(&buf, "Backend metrics:")
	fmt.Fprintf(&buf, "  %*s %12s %12s %12s\n", -maxLen, "Server", "Count", "Egress", "Ingress")
	for _, s := range serverNames {
		fmt.Fprintf(&buf, "  %*s %12d %12d %12d\n", -maxLen, s, totals[s].numConnections, totals[s].numBytesSent, totals[s].numBytesReceived)
	}

	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "Event counts:")
	p.eventsmu.Lock()
	events := make([]string, 0, len(p.events))
	for k := range p.events {
		events = append(events, k)
	}
	sort.Strings(events)
	for _, e := range events {
		fmt.Fprintf(&buf, "  %6d x %s\n", p.events[e], e)
	}
	p.eventsmu.Unlock()

	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "Current connections:")
	keys := make([]connKey, 0, len(p.connections))
	for k := range p.connections {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		sa := p.connections[keys[i]].Annotation(serverNameKey, "").(string)
		sb := p.connections[keys[j]].Annotation(serverNameKey, "").(string)
		if sa == sb {
			a := keys[i].src.String() + " " + keys[i].dst.String()
			b := keys[j].src.String() + " " + keys[j].dst.String()
			return a < b
		}
		return sa < sb
	})
	for _, k := range keys {
		c := p.connections[k]
		startTime := c.Annotation(startTimeKey, time.Time{}).(time.Time)
		totalTime := time.Since(startTime)
		remote := c.RemoteAddr().Network() + ":" + c.RemoteAddr().String()

		var streams []*netw.QUICStream

		switch cc := c.Conn.(type) {
		case *net.TCPConn:
			remote += " TLS"
		case *netw.QUICConn:
			remote += " QUIC"
			streams = cc.Streams()
			sort.Slice(streams, func(i, j int) bool {
				return streams[i].StreamID() < streams[j].StreamID()
			})
		default:
			remote += fmt.Sprintf(" %T", c.Conn)
		}
		fmt.Fprintf(&buf, "  %s <=> %s %s %s\n", remote, idnaToUnicode(connServerName(c)), connMode(c), connProto(c))
		var intAddr string
		if intConn := connIntConn(c); intConn != nil {
			intAddr = intConn.RemoteAddr().Network() + ":" + intConn.RemoteAddr().String()
			if len(streams) == 0 {
				fmt.Fprintf(&buf, "  %*s <-> %s\n", len(remote), "", intAddr)
			}
		}
		for _, stream := range streams {
			addr := intAddr
			if addr == "" {
				addr = stream.BridgeAddr()
			}
			if addr == "" {
				addr = "local"
			}
			streamID := stream.StreamID()
			var dir string
			// bit 0: 0 -> client initiated, 1 -> server initiated
			// bit 1: 0 -> bidirectional, 1 -> unidirectional
			switch streamID & 0x3 {
			case 0x0, 0x1:
				// bidi, client or server initiated
				dir = "<->"
			case 0x2:
				// uni, client initiated
				dir = "-->"
			case 0x3:
				// uni, server initiated
				dir = "<--"
			}
			fmt.Fprintf(&buf, "  %*s %s %s stream %d\n", len(remote), "", dir,
				addr, streamID,
			)
		}
		if cert := connClientCert(c); cert != nil {
			fmt.Fprintf(&buf, "          X509 [%s]\n", certSummary(cert))
		}
		fmt.Fprintf(&buf, "          Elapsed:%s Egress:%.1f KB (%.1f KB/s) Ingress:%.1f KB (%.1f KB/s) \n",
			totalTime.Truncate(100*time.Millisecond),
			float32(c.BytesSent())/1000, float32(c.BytesSent())/float32(totalTime)*float32(time.Second)/1000,
			float32(c.BytesReceived())/1000, float32(c.BytesReceived())/float32(totalTime)*float32(time.Second)/1000)
		fmt.Fprintln(&buf)
	}

	for i, be := range p.cfg.Backends {
		sso := ""
		if be.SSO != nil {
			sso = fmt.Sprintf(" SSO %s %s", be.SSO.Provider, strings.Join(be.SSO.Paths, ","))
		}
		clientAuth := ""
		if be.ClientAuth != nil {
			clientAuth = " TLS ClientAuth"
		}
		protos := ""
		if be.ALPNProtos != nil {
			protos = " ALPN[" + strings.Join(*be.ALPNProtos, ",") + "]"
			if be.BackendProto != nil {
				protos += "->" + *be.BackendProto
			}
		}
		fmt.Fprintf(&buf, "Backend[%d] %s%s%s%s\n", i, be.Mode, clientAuth, protos, sso)
		for j, sn := range be.ServerNames {
			if nn := idnaToUnicode(sn); sn != nn {
				fmt.Fprintf(&buf, "  ServerName[%d]: %s (%s)\n", j, nn, sn)
			} else {
				fmt.Fprintf(&buf, "  ServerName[%d]: %s\n", j, sn)
			}
		}
		for j, a := range be.Addresses {
			fmt.Fprintf(&buf, "  Address[%d]: %s\n", j, a)
		}
		if len(be.localHandlers) > 0 {
			fmt.Fprintf(&buf, "  Local Handlers:\n")
			type item struct {
				bypass   string
				hostPath string
				desc     string
			}
			items := make([]item, 0, len(be.localHandlers))
			var sz int
			for _, h := range be.localHandlers {
				bypass := " "
				if h.ssoBypass {
					bypass = "X"
				}
				host := "<any>"
				if h.host != "" {
					host = h.host
				}
				hostPath := host + h.path
				items = append(items, item{bypass, hostPath, h.desc})
				if l := len(hostPath); l > sz {
					sz = l
				}
			}
			for _, i := range items {
				fmt.Fprintf(&buf, "    [%s] https://%*s %s\n", i.bypass, -sz, i.hostPath, i.desc)
			}
		}
		fmt.Fprintln(&buf)
	}

	fmt.Fprintln(&buf, "Runtime:")
	fmt.Fprintf(&buf, "  Uptime:       %12s\n", time.Since(p.startTime).Truncate(time.Second))
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fmt.Fprintf(&buf, "  NumCPU:       %12d\n", runtime.NumCPU())
	fmt.Fprintf(&buf, "  NumGoroutine: %12d\n", runtime.NumGoroutine())
	fmt.Fprintf(&buf, "  Mallocs:      %12d\n", memStats.Mallocs)
	fmt.Fprintf(&buf, "  Frees:        %12d\n", memStats.Frees)
	fmt.Fprintf(&buf, "  HeapObjects:  %12d\n", memStats.HeapObjects)
	fmt.Fprintf(&buf, "  HeapAlloc:    %12d\n", memStats.HeapAlloc)
	fmt.Fprintf(&buf, "  NextGC:       %12d\n", memStats.NextGC)
	fmt.Fprintf(&buf, "  NumGC:        %12d\n", memStats.NumGC)
	fmt.Fprintln(&buf)
	memProf := make([]runtime.MemProfileRecord, 100)
	fmt.Fprintln(&buf, "Memory Profile:")
	if n, ok := runtime.MemProfile(memProf, false); ok {
		type item struct {
			b int64
			n int64
			f string
		}
		items := make([]item, 0, n)
		for _, p := range memProf[:n] {
			fn := runtime.FuncForPC(p.Stack0[0])
			items = append(items, item{p.InUseBytes(), p.InUseObjects(), fn.Name()})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].b == items[j].b {
				return items[i].f < items[j].f
			}
			return items[i].b > items[j].b
		})
		for _, item := range items {
			fmt.Fprintf(&buf, "%12d %4d %s()\n", item.b, item.n, item.f)
		}
	} else {
		fmt.Fprintf(&buf, "Too many MemProfile records: %d\n", n)
	}
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "Goroutines:")
	goProf := make([]runtime.StackRecord, runtime.NumGoroutine()+10)
	if n, ok := runtime.GoroutineProfile(goProf); ok {
		count := make(map[string]int)
		for _, p := range goProf[:n] {
			var funcs []string
			for i := range p.Stack0 {
				if p.Stack0[i] == 0 {
					break
				}
				funcs = append(funcs, runtime.FuncForPC(p.Stack0[i]).Name())
			}
			if len(funcs) < 2 {
				continue
			}
			count[funcs[len(funcs)-2]]++
		}
		type item struct {
			n int
			f string
		}
		items := make([]item, 0, len(count))
		for k, v := range count {
			items = append(items, item{v, k})

		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].n == items[j].n {
				return items[i].f < items[j].f
			}
			return items[i].n > items[j].n
		})
		for _, item := range items {
			fmt.Fprintf(&buf, "  %4d %s()\n", item.n, item.f)
		}
	} else {
		fmt.Fprintf(&buf, "Too many GoroutineProfile records: %d\n", n)
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		fmt.Fprintln(&buf)
		fmt.Fprintln(&buf, "Buildinfo:")
		fmt.Fprintln(&buf, info)
	}
}

func (p *Proxy) configHandler(w http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	cfg := p.cfg.clone()
	p.mu.Unlock()
	for _, p := range cfg.OIDCProviders {
		p.ClientSecret = "**REDACTED**"
	}
	for _, be := range cfg.Backends {
		if be.SSO == nil || be.SSO.LocalOIDCServer == nil {
			continue
		}
		for _, client := range be.SSO.LocalOIDCServer.Clients {
			client.Secret = "**REDACTED**"
		}
	}
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	enc.Encode(cfg)
	enc.Close()
}

func (p *Proxy) faviconHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(iconBytes)))
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Write(iconBytes)
}
