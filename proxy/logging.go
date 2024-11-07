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
	"log"
)

type logType int

const (
	logConnection logType = iota
	logRequest
	logError
)

func (p *Proxy) logConnF(format string, args ...any) {
	if p.cfg == nil || !shouldLog(logConnection, p.cfg.LogFilter) {
		return
	}
	log.Printf(format, args...)
}

func (p *Proxy) logError(args ...any) {
	if p.cfg != nil && !shouldLog(logError, p.cfg.LogFilter) {
		return
	}
	log.Print(args...)
}

func (p *Proxy) logErrorF(format string, args ...any) {
	if p.cfg != nil && !shouldLog(logError, p.cfg.LogFilter) {
		return
	}
	log.Printf(format, args...)
}

func (be *Backend) logConnF(format string, args ...any) {
	if !shouldLog(logConnection, be.LogFilter, be.defaultLogFilter) {
		return
	}
	log.Printf(format, args...)
}

func (be *Backend) logRequestF(format string, args ...any) {
	if !shouldLog(logRequest, be.LogFilter, be.defaultLogFilter) {
		return
	}
	log.Printf(format, args...)
}

func (be *Backend) logErrorF(format string, args ...any) {
	if !shouldLog(logError, be.LogFilter, be.defaultLogFilter) {
		return
	}
	log.Printf(format, args...)
}

func (be *Backend) logError(args ...any) {
	if !shouldLog(logError, be.LogFilter, be.defaultLogFilter) {
		return
	}
	log.Print(args...)
}

func shouldLog(typ logType, f ...LogFilter) bool {
	if typ == logConnection {
		for _, ff := range f {
			if ff.Connections != nil {
				return *ff.Connections
			}
		}
		return true
	}
	if typ == logRequest {
		for _, ff := range f {
			if ff.Requests != nil {
				return *ff.Requests
			}
		}
		return true
	}
	if typ == logError {
		for _, ff := range f {
			if ff.Errors != nil {
				return *ff.Errors
			}
		}
		return true
	}

	return true
}

func (p *Proxy) extLogger() logger {
	return logger{p.logErrorF, p.logError}
}

func (be *Backend) extLogger() logger {
	return logger{be.logErrorF, be.logError}
}

type logger struct {
	f1 func(string, ...any)
	f2 func(...any)
}

func (logger) Debug(args ...any) {}

func (logger) Debugf(f string, args ...any) {}

func (l logger) Info(args ...any) {
	if l.f2 == nil {
		return
	}
	l.f2(append([]any{"INF "}, args...)...)
}

func (l logger) Infof(f string, args ...any) {
	if l.f1 == nil {
		return
	}
	l.f1("INF "+f, args...)
}

func (l logger) Error(args ...any) {
	if l.f2 == nil {
		return
	}
	l.f2(append([]any{"ERR "}, args...)...)
}

func (l logger) Errorf(f string, args ...any) {
	if l.f1 == nil {
		return
	}
	l.f1("ERR "+f, args...)
}

func (l logger) Fatal(args ...any) {
	if l.f2 == nil {
		return
	}
	l.f2(append([]any{"FATAL "}, args...)...)
}

func (l logger) Fatalf(f string, args ...any) {
	if l.f1 == nil {
		return
	}
	l.f1("FATAL "+f, args...)
}
