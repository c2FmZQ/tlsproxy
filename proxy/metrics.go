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
	"html/template"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/counter"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

//go:embed c2.png
var iconBytes []byte

//go:embed metrics-template.html
var metricsEmbed string
var metricsTemplate *template.Template

func init() {
	metricsTemplate = template.Must(template.New("metrics").Parse(metricsEmbed))
}

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

func (p *Proxy) setCounters(c *netw.Conn, serverName string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metrics == nil {
		p.metrics = make(map[string]*backendMetrics)
	}
	m := p.metrics[serverName]
	if m == nil {
		m = &backendMetrics{
			numConnections:   counter.New(time.Minute, time.Second),
			numBytesSent:     counter.New(time.Minute, time.Second),
			numBytesReceived: counter.New(time.Minute, time.Second),
		}
		p.metrics[serverName] = m
	}
	m.numConnections.Incr(1)
	c.SetCounters(m.numBytesSent, m.numBytesReceived)
}

func (p *Proxy) removeConn(c *netw.Conn) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.connections, connKey{c.LocalAddr(), c.RemoteAddr(), c.StreamID()})
	return len(p.connections)
}

func (p *Proxy) metricsHandler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	if v := req.Form.Get("refresh"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			w.Header().Set("refresh", strconv.Itoa(i))
		}
	}

	type backendMetric struct {
		ServerName     string
		NumConnections int64
		Egress         string
		Ingress        string
		EgressRate     string
		IngressRate    string
	}
	type proxyEvent struct {
		Description string
		Count       int64
	}
	type connDest struct {
		Address   string
		Stream    string
		Direction string
	}
	type connection struct {
		SourceAddr   string
		Type         string
		ServerName   string
		Mode         string
		Proto        string
		Destinations []connDest
		Time         string
		EgressBytes  string
		EgressRate   string
		IngressBytes string
		IngressRate  string
		ClientID     string
	}
	type handler struct {
		Bypass   bool
		HostPath string
		Desc     string
	}
	type backend struct {
		Mode         string
		ALPNProtos   string
		BackendProto string
		ClientAuth   string
		SSO          string
		ServerNames  []string
		Addresses    []string
		Handlers     []handler
	}
	type runtimeData struct {
		Uptime       string
		NumCPU       int
		NumGoroutine int
		Mallocs      uint64
		Frees        uint64
		HeapObjects  uint64
		HeapAlloc    uint64
		NextGC       uint64
		NumGC        uint32
	}
	type memoryProf struct {
		Size  int64
		Count int64
		Func  string
	}
	type goroutine struct {
		Count int
		Func  string
	}

	var data struct {
		Version     string
		Metrics     []backendMetric
		Events      []proxyEvent
		Connections []connection
		Backends    []backend
		Runtime     runtimeData
		Memory      []memoryProf
		Goroutines  []goroutine
		BuildInfo   string
		Config      string
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		data.BuildInfo = info.String()
		const v = "main.Version="
		for _, s := range info.Settings {
			if p := strings.Index(s.Value, v); p >= 0 && s.Key == "-ldflags" {
				data.Version = strings.TrimSuffix(s.Value[p+len(v):], `"`)
			}
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

	var serverNames []string
	var maxLen int
	for k := range totals {
		if n := len(k); n > maxLen {
			maxLen = n
		}
		serverNames = append(serverNames, k)
	}
	sort.Strings(serverNames)

	for _, s := range serverNames {
		data.Metrics = append(data.Metrics, backendMetric{
			ServerName:     s,
			NumConnections: totals[s].numConnections.Value(),
			Egress:         formatSize10(totals[s].numBytesSent.Value()),
			Ingress:        formatSize10(totals[s].numBytesReceived.Value()),
			EgressRate:     formatSize10(totals[s].numBytesSent.Rate(time.Minute)) + "/s",
			IngressRate:    formatSize10(totals[s].numBytesReceived.Rate(time.Minute)) + "/s",
		})
	}

	p.eventsmu.Lock()
	events := make([]string, 0, len(p.events))
	for k := range p.events {
		events = append(events, k)
	}
	sort.Strings(events)

	for _, e := range events {
		data.Events = append(data.Events, proxyEvent{
			Description: e,
			Count:       p.events[e],
		})
	}
	p.eventsmu.Unlock()

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

		connection := connection{
			SourceAddr: remote,
			ServerName: idnaToUnicode(connServerName(c)),
			Mode:       connMode(c),
			Proto:      connProto(c),
		}
		var streams []*netw.QUICStream

		switch cc := c.Conn.(type) {
		case *net.TCPConn:
			connection.Type = "TLS"
		case *netw.QUICConn:
			connection.Type = "QUIC"
			streams = cc.Streams()
			sort.Slice(streams, func(i, j int) bool {
				return streams[i].StreamID() < streams[j].StreamID()
			})
		default:
			connection.Type = fmt.Sprintf(" %T", c.Conn)
		}

		var intAddr string
		if intConn := connIntConn(c); intConn != nil {
			intAddr = intConn.RemoteAddr().Network() + ":" + intConn.RemoteAddr().String()
			if len(streams) == 0 {
				connection.Destinations = append(connection.Destinations, connDest{
					Address:   intAddr,
					Direction: "<->",
				})
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
			connection.Destinations = append(connection.Destinations, connDest{
				Address:   addr,
				Stream:    fmt.Sprintf("stream %d", streamID),
				Direction: dir,
			})
		}
		if cert := connClientCert(c); cert != nil {
			connection.ClientID = certSummary(cert)
		}
		connection.Time = totalTime.Truncate(100 * time.Millisecond).String()
		connection.EgressBytes = formatSize10(c.BytesSent())
		connection.EgressRate = formatSize10(c.ByteRateSent()) + "/s"
		connection.IngressBytes = formatSize10(c.BytesReceived())
		connection.IngressRate = formatSize10(c.ByteRateReceived()) + "/s"

		data.Connections = append(data.Connections, connection)
	}

	for _, be := range p.cfg.Backends {
		backend := backend{
			Mode: be.Mode,
		}
		if be.SSO != nil {
			backend.SSO = fmt.Sprintf(" SSO %s %s", be.SSO.Provider, strings.Join(be.SSO.Paths, ","))
		}
		if be.ClientAuth != nil {
			backend.ClientAuth = " TLS ClientAuth"
		}
		if be.ALPNProtos != nil {
			protos := " ALPN[" + strings.Join(*be.ALPNProtos, ",") + "]"
			if be.BackendProto != nil {
				protos += "->" + *be.BackendProto
			}
			backend.ALPNProtos = protos
		}
		for _, sn := range be.ServerNames {
			backend.ServerNames = append(backend.ServerNames, idnaToUnicode(sn))
		}
		backend.Addresses = slices.Clone(be.Addresses)
		for _, h := range be.localHandlers {
			host := "<any>"
			if h.host != "" {
				host = h.host
			}
			backend.Handlers = append(backend.Handlers, handler{
				Bypass:   h.ssoBypass,
				HostPath: host + h.path,
				Desc:     h.desc,
			})
		}
		data.Backends = append(data.Backends, backend)
	}

	data.Runtime.Uptime = time.Since(p.startTime).Truncate(time.Second).String()
	data.Runtime.NumCPU = runtime.NumCPU()
	data.Runtime.NumGoroutine = runtime.NumGoroutine()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	data.Runtime.Mallocs = memStats.Mallocs
	data.Runtime.Frees = memStats.Frees
	data.Runtime.HeapObjects = memStats.HeapObjects
	data.Runtime.HeapAlloc = memStats.HeapAlloc
	data.Runtime.NextGC = memStats.NextGC
	data.Runtime.NumGC = memStats.NumGC

	memProf := make([]runtime.MemProfileRecord, 200)
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
			data.Memory = append(data.Memory, memoryProf{
				Size:  item.b,
				Count: item.n,
				Func:  item.f,
			})
		}
	}

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
			data.Goroutines = append(data.Goroutines, goroutine{
				Count: item.n,
				Func:  item.f,
			})
		}
	}

	cfg := p.cfg.clone()
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
	var cfgbuf bytes.Buffer
	enc := yaml.NewEncoder(&cfgbuf)
	enc.SetIndent(2)
	enc.Encode(cfg)
	enc.Close()
	data.Config = cfgbuf.String()

	metricsTemplate.Execute(&buf, data)
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("content-length", fmt.Sprintf("%d", buf.Len()))
}

func (p *Proxy) faviconHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(iconBytes)))
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Write(iconBytes)
}
