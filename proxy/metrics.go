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
	"log"
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
	runtime.SetMutexProfileFraction(1)
	runtime.MemProfileRate = 1
}

func (p *Proxy) recordEvent(msg string) {
	p.eventsmu.Lock()
	defer p.eventsmu.Unlock()
	if p.events == nil {
		p.events = make(map[string]int64)
	}
	p.events[msg]++
}

type counterSetter interface {
	SetCounters(*counter.Counter, *counter.Counter)
}

func (p *Proxy) setCounters(c counterSetter, serverName string) {
	p.mu.RLock()
	if p.metrics != nil {
		if m := p.metrics[serverName]; m != nil {
			m.numConnections.Incr(1)
			c.SetCounters(m.numBytesSent, m.numBytesReceived)
			p.mu.RUnlock()
			return
		}
	}
	p.mu.RUnlock()

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
		ViaAddr      string
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
	type beConnection struct {
		SourceAddr      string
		DestinationAddr string
		Mode            string
		Proto           string
		ProxyProto      string
		Time            string
		EgressBytes     string
		EgressRate      string
		IngressBytes    string
		IngressRate     string
	}
	type beConnectionList struct {
		ServerName  string
		Connections []beConnection
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
	type mutexProf struct {
		Count  int64
		Cycles int64
		Func   string
	}
	type goroutine struct {
		Count int
		Func  string
	}

	var data struct {
		Version            string
		Metrics            []backendMetric
		Events             []proxyEvent
		Connections        []connection
		BackendConnections []beConnectionList
		Backends           []backend
		Runtime            runtimeData
		Memory             []memoryProf
		Mutex              []mutexProf
		Goroutines         []goroutine
		BuildInfo          string
		Config             string
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

	p.mu.RLock()
	defer p.mu.RUnlock()

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

	conns := p.inConns.slice()
	sort.Slice(conns, func(i, j int) bool {
		sa := conns[i].Annotation(serverNameKey, "").(string)
		sb := conns[j].Annotation(serverNameKey, "").(string)
		if sa == sb {
			a := conns[i].LocalAddr().String() + " " + conns[i].RemoteAddr().String()
			b := conns[j].LocalAddr().String() + " " + conns[j].RemoteAddr().String()
			return a < b
		}
		return sa < sb
	})

	for _, c := range conns {
		startTime := c.Annotation(startTimeKey, time.Time{}).(time.Time)
		totalTime := time.Since(startTime)
		remote := c.RemoteAddr().Network() + ":" + c.RemoteAddr().String()

		connection := connection{
			SourceAddr: remote,
			ServerName: idnaToUnicode(connServerName(c)),
			Mode:       connMode(c),
			Proto:      connProto(c),
		}
		if isProxyProtoConn(c) {
			connection.ViaAddr = c.LocalAddr().Network() + ":" + c.LocalAddr().String()
		}
		if up := connHTTPUpgrade(c); up != "" {
			connection.Proto += "+" + up
		}
		var streams []*netw.QUICStream

		switch cc := c.(type) {
		case *netw.Conn:
			connection.Type = "TLS"
		case *netw.QUICConn:
			connection.Type = "QUIC"
			streams = cc.Streams()
			sort.Slice(streams, func(i, j int) bool {
				return streams[i].StreamID() < streams[j].StreamID()
			})
		default:
			connection.Type = fmt.Sprintf(" %T", c)
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

	beConns := make(map[string][]beConnection)

	for _, c := range p.outConns.slice() {
		sn := connServerName(c)
		startTime := c.Annotation(startTimeKey, time.Time{}).(time.Time)
		totalTime := time.Since(startTime)
		connection := beConnection{
			SourceAddr:      c.LocalAddr().Network() + ":" + c.LocalAddr().String(),
			DestinationAddr: c.RemoteAddr().Network() + ":" + c.RemoteAddr().String(),
			Mode:            connMode(c),
			Proto:           connProto(c),
			ProxyProto:      connProxyProto(c),
			Time:            totalTime.Truncate(100 * time.Millisecond).String(),
			EgressBytes:     formatSize10(c.BytesSent()),
			EgressRate:      formatSize10(c.ByteRateSent()) + "/s",
			IngressBytes:    formatSize10(c.BytesReceived()),
			IngressRate:     formatSize10(c.ByteRateReceived()) + "/s",
		}
		beConns[sn] = append(beConns[sn], connection)
	}
	var beConnServerNames []string
	for k := range beConns {
		beConnServerNames = append(beConnServerNames, k)
	}
	sort.Strings(beConnServerNames)
	for _, sn := range beConnServerNames {
		data.BackendConnections = append(data.BackendConnections, beConnectionList{
			ServerName:  idnaToUnicode(sn),
			Connections: beConns[sn],
		})
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

	getFunc := func(stack [32]uintptr, n int) string {
		var out []string
		for i := 0; i < n && stack[i] != 0; i++ {
			fn := runtime.FuncForPC(stack[i])
			fnName := fn.Name()
			out = append(out, fmt.Sprintf("%s+0x%x", fnName, stack[i]-fn.Entry()))
			if !strings.HasPrefix(fnName, "runtime.") && !strings.HasPrefix(fnName, "sync.") {
				break
			}
		}
		slices.Reverse(out)
		if len(out) <= 2 {
			return strings.Join(out, " -> ")
		}
		return out[0] + " -> ... -> " + out[len(out)-1]
	}
	memProfSize, _ := runtime.MemProfile(nil, false)
	memProf := make([]runtime.MemProfileRecord, memProfSize+100)
	if n, ok := runtime.MemProfile(memProf, false); ok {
		itemMap := make(map[uintptr]memoryProf)
		for _, p := range memProf[:n] {
			key := p.Stack0[0]
			it, ok := itemMap[key]
			if !ok {
				it = memoryProf{Func: getFunc(p.Stack0, 1)}
			}
			it.Size += p.InUseBytes()
			it.Count += p.InUseObjects()
			itemMap[key] = it
		}
		var items []memoryProf
		for _, it := range itemMap {
			if it.Size < 102400 {
				continue
			}
			items = append(items, it)
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Size == items[j].Size {
				return items[i].Func < items[j].Func
			}
			return items[i].Size > items[j].Size
		})
		if len(items) > 25 {
			items = items[:25]
		}
		data.Memory = items
	} else {
		log.Printf("ERR MemoryProfile n=%d", n)
	}

	mutexProfile := make([]runtime.BlockProfileRecord, 200)
	if n, ok := runtime.MutexProfile(mutexProfile); ok {
		itemMap := make(map[string]mutexProf)
		for _, p := range mutexProfile[:n] {
			key := getFunc(p.Stack0, 5)
			it, ok := itemMap[key]
			if !ok {
				it = mutexProf{Func: key}
			}
			it.Count += p.Count
			it.Cycles += p.Cycles
			itemMap[key] = it
		}
		items := make([]mutexProf, 0, len(itemMap))
		for _, item := range itemMap {
			items = append(items, item)
		}
		items = slices.DeleteFunc(items, func(e mutexProf) bool {
			return e.Cycles < 1000000
		})
		sort.Slice(items, func(i, j int) bool {
			if items[i].Cycles == items[j].Cycles {
				return items[i].Func < items[j].Func
			}
			return items[i].Cycles > items[j].Cycles
		})
		if len(items) > 25 {
			items = items[:25]
		}
		data.Mutex = items
	} else {
		log.Printf("ERR MutexProfile n=%d", n)
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
	} else {
		log.Printf("ERR GoroutineProfile n=%d", n)
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
