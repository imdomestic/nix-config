package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var transportSequence atomic.Uint64

type upstreamTransportFailure struct {
	cause            error
	id, class, phase string
	elapsed          time.Duration
}

func (f *upstreamTransportFailure) Error() string {
	return "upstream transport failed; request was not replayed"
}
func (f *upstreamTransportFailure) Unwrap() error { return f.cause }

type upstreamTrace struct {
	mu                                  sync.Mutex
	phase, protocol                     string
	gotConn, reused, written, firstByte bool
	idle                                time.Duration
}

func newUpstreamLogger() *log.Logger { return log.New(os.Stderr, "", 0) }

func (t *upstreamTrace) hooks() *httptrace.ClientTrace {
	mark := func(phase string) { t.mu.Lock(); t.phase = phase; t.mu.Unlock() }
	return &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { mark("dns") },
		ConnectStart:      func(string, string) { mark("connect") },
		TLSHandshakeStart: func() { mark("tls") },
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			switch state.NegotiatedProtocol {
			case "h2", "http/1.1":
				t.protocol = state.NegotiatedProtocol
			default:
				t.protocol = "unknown"
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.gotConn, t.reused, t.idle, t.phase = true, info.Reused, info.IdleTime, "request_write"
			if connection, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
				switch protocol := connection.ConnectionState().NegotiatedProtocol; protocol {
				case "h2", "http/1.1":
					t.protocol = protocol
				}
			}
		},
		WroteHeaders: func() { mark("request_write") },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if info.Err == nil {
				t.written = true
				t.phase = "response_headers"
			}
		},
		GotFirstResponseByte: func() { t.mu.Lock(); t.firstByte = true; t.phase = "response_headers"; t.mu.Unlock() },
	}
}

func classifyTransportFailure(ctx context.Context, err error, phase string, written, firstByte bool) string {
	if errors.Is(ctx.Err(), context.Canceled) && errors.Is(err, context.Canceled) {
		return "client_canceled"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.Timeout() {
			return "dns_timeout"
		}
		return "dns_error"
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	if errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &certificate) {
		return "tls_certificate_error"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		if phase == "response_headers" && written && !firstByte {
			return "response_header_timeout"
		}
		switch phase {
		case "connect":
			return "connect_timeout"
		case "tls":
			return "tls_timeout"
		case "request_write":
			return "request_write_timeout"
		}
		return "transport_timeout"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	if errors.Is(err, syscall.EPIPE) {
		return "broken_pipe"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "unexpected_eof"
	}
	if errors.Is(err, io.EOF) {
		return "upstream_eof"
	}
	if errors.Is(err, net.ErrClosed) {
		return "connection_closed"
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "tls_error"
	}
	var operation *net.OpError
	if errors.As(err, &operation) && operation.Op == "dial" {
		return "connect_error"
	}
	return "transport_error"
}

func (p *proxy) doUpstream(request *http.Request, action string, bodyBytes int, model string) (*http.Response, error) {
	started := time.Now()
	id := fmt.Sprintf("u-%x-%x", started.UnixNano(), transportSequence.Add(1))
	trace := &upstreamTrace{phase: "connection_wait", protocol: "unknown"}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace.hooks()))
	response, err := p.client.Do(request)
	if err == nil {
		return response, nil
	}
	trace.mu.Lock()
	phase, protocol, connected, reused, written, firstByte, idle := trace.phase, trace.protocol, trace.gotConn, trace.reused, trace.written, trace.firstByte, trace.idle
	trace.mu.Unlock()
	elapsed := time.Since(started)
	class := classifyTransportFailure(request.Context(), err, phase, written, firstByte)
	if !validModel(model) {
		model = "unspecified"
	}
	if !nativeMethods[action] {
		action = "unspecified"
	}
	leaf := err
	for i := 0; i < 8; i++ {
		next := errors.Unwrap(leaf)
		if next == nil {
			break
		}
		leaf = next
	}
	if p.transportLog != nil {
		priority := 4
		if class == "client_canceled" {
			priority = 5
		}
		// Prefix is at the start, so journald retains warnings on notice-only hosts.
		// Never log err.Error(), headers, URLs, request bodies or account identifiers.
		p.transportLog.Printf("<%d>agy-proxy upstream_transport_failure id=%s action=%s model=%s class=%s phase=%s elapsed_ms=%d request_bytes=%d request_written=%t first_byte=%t conn_obtained=%t conn_reused=%t conn_idle_ms=%d protocol=%s cause_type=%T replayed=false", priority, id, action, model, class, phase, elapsed.Milliseconds(), bodyBytes, written, firstByte, connected, reused, idle.Milliseconds(), protocol, leaf)
	}
	return response, &upstreamTransportFailure{cause: err, id: id, class: class, phase: phase, elapsed: elapsed}
}

func writeUpstreamFailure(w http.ResponseWriter, err error, openai bool) {
	errorBody := map[string]any{"code": 502, "message": "upstream transport failed; request was not replayed"}
	if openai {
		errorBody["type"] = "server_error"
		errorBody["param"] = nil
	}
	var failure *upstreamTransportFailure
	if errors.As(err, &failure) {
		errorBody["diagnostic_id"] = failure.id
		errorBody["failure_class"] = failure.class
		errorBody["upstream_phase"] = failure.phase
		errorBody["elapsed_ms"] = failure.elapsed.Milliseconds()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(502)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": errorBody})
}
