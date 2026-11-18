package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type diagnosticTimeout struct{}

func (diagnosticTimeout) Error() string   { return "private raw network diagnostics" }
func (diagnosticTimeout) Timeout() bool   { return true }
func (diagnosticTimeout) Temporary() bool { return true }

type diagnosticRoundTripper func(*http.Request) (*http.Response, error)

func (f diagnosticRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportClassificationIsSpecificButNeverUsesErrorMessages(t *testing.T) {
	for _, tc := range []struct {
		err            error
		phase          string
		written, first bool
		want           string
	}{
		{&net.DNSError{Err: "private-host", IsTimeout: true}, "dns", false, false, "dns_timeout"},
		{&net.DNSError{Err: "private-host"}, "dns", false, false, "dns_error"},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "connect", false, false, "connect_error"},
		{diagnosticTimeout{}, "response_headers", true, false, "response_header_timeout"},
		{diagnosticTimeout{}, "response_headers", true, true, "transport_timeout"},
		{diagnosticTimeout{}, "request_write", false, false, "request_write_timeout"},
		{diagnosticTimeout{}, "tls", false, false, "tls_timeout"},
		{diagnosticTimeout{}, "connect", false, false, "connect_timeout"},
		{x509.UnknownAuthorityError{}, "tls", false, false, "tls_certificate_error"},
		{tls.RecordHeaderError{}, "tls", false, false, "tls_error"},
		{syscall.ECONNRESET, "response_headers", true, false, "connection_reset"},
		{syscall.EPIPE, "request_write", false, false, "broken_pipe"},
		{io.EOF, "response_headers", true, false, "upstream_eof"},
		{io.ErrUnexpectedEOF, "response_headers", true, false, "unexpected_eof"},
		{net.ErrClosed, "response_headers", true, false, "connection_closed"},
		{errors.New("private arbitrary error"), "connection_wait", false, false, "transport_error"},
	} {
		wrapped := &url.Error{Op: "POST", URL: "https://private.invalid/?token=private", Err: tc.err}
		if got := classifyTransportFailure(context.Background(), wrapped, tc.phase, tc.written, tc.first); got != tc.want {
			t.Errorf("got %s want %s", got, tc.want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if classifyTransportFailure(ctx, context.Canceled, "response_headers", true, false) != "client_canceled" {
		t.Fatal("client cancellation misclassified")
	}
	if classifyTransportFailure(ctx, io.EOF, "response_headers", true, false) != "upstream_eof" {
		t.Fatal("a later caller cancellation masked an independent EOF")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if classifyTransportFailure(ctx, context.DeadlineExceeded, "response_headers", true, false) != "context_deadline" {
		t.Fatal("caller deadline misclassified")
	}
}

func TestTransportFailurePublicCorrelationAndLogPrivacy(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Fatal("fake transport unexpectedly contacted server") }, fixedCredentials{credential{AccessToken: "PRIVATE_GOOGLE_TOKEN", Project: "PRIVATE_PROJECT"}})
	p.openaiCompat = true
	var output bytes.Buffer
	p.transportLog = log.New(&output, "", 0)
	p.client.Transport = diagnosticRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.GetBody != nil {
			t.Error("generation became replayable")
		}
		trace := httptrace.ContextClientTrace(r.Context())
		trace.GotConn(httptrace.GotConnInfo{Reused: true, IdleTime: 3 * time.Second})
		trace.WroteHeaders()
		trace.WroteRequest(httptrace.WroteRequestInfo{})
		return nil, &url.Error{Op: "POST", URL: "https://PRIVATE_HOST.invalid/?token=PRIVATE_KEY", Err: diagnosticTimeout{}}
	})
	w := request(p, "POST", "/v1/chat/completions", `{"model":"gemini-test","messages":[{"role":"user","content":"PRIVATE_PROMPT"}],"stream":true}`)
	if w.Code != 502 || calls.Load() != 1 {
		t.Fatal("transport failure status/replay policy changed")
	}
	var envelope struct {
		Error struct {
			ID      string `json:"diagnostic_id"`
			Class   string `json:"failure_class"`
			Phase   string `json:"upstream_phase"`
			Message string
			Code    int
			Type    string
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || !strings.HasPrefix(envelope.Error.ID, "u-") || envelope.Error.Class != "response_header_timeout" || envelope.Error.Phase != "response_headers" || envelope.Error.Code != 502 || envelope.Error.Type != "server_error" {
		t.Fatalf("missing safe correlation metadata: %s", w.Body.String())
	}
	if envelope.Error.Message != "upstream transport failed; request was not replayed" {
		t.Fatal("existing error message contract changed")
	}
	text := output.String()
	for _, want := range []string{"<4>agy-proxy upstream_transport_failure", envelope.Error.ID, "model=gemini-test", "request_written=true", "conn_reused=true", "conn_idle_ms=3000", "replayed=false", "cause_type="} {
		if !strings.Contains(text, want) {
			t.Errorf("missing safe field %s", want)
		}
	}
	for _, secret := range []string{"PRIVATE_", "private raw", "https://", "Authorization", "Bearer"} {
		if strings.Contains(text, secret) || strings.Contains(w.Body.String(), secret) {
			t.Fatalf("sensitive diagnostics leaked: %s", secret)
		}
	}
}

func TestRealHeaderTimeoutIsDiagnosedAndNotRetried(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}, fixedCredentials{})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 40 * time.Millisecond
	p.client.Transport = transport
	defer transport.CloseIdleConnections()
	var logs bytes.Buffer
	p.transportLog = log.New(&logs, "", 0)
	_, err := p.upstream(context.Background(), "generateContent", []byte(`{"private":"never logged"}`), "private token", "gemini-test")
	var failure *upstreamTransportFailure
	if !errors.As(err, &failure) || failure.class != "response_header_timeout" || calls.Load() != 1 {
		t.Fatalf("header timeout not observed safely: %T calls %d", err, calls.Load())
	}
	if !strings.Contains(logs.String(), "request_written=true") || strings.Contains(logs.String(), "never logged") {
		t.Fatal("wrong timeout stage or privacy failure")
	}
}

func TestReusedConnectionEOFKeepsNoReplayPolicy(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}, fixedCredentials{})
	var logs bytes.Buffer
	p.transportLog = log.New(&logs, "", 0)
	response, err := p.upstream(context.Background(), "generateContent", []byte(`{"request":"one"}`), "private token", "gemini-test")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	_, err = p.upstream(context.Background(), "generateContent", []byte(`{"request":"two"}`), "private token", "gemini-test")
	var failure *upstreamTransportFailure
	if !errors.As(err, &failure) || (failure.class != "upstream_eof" && failure.class != "connection_reset") || calls.Load() != 2 {
		t.Fatalf("reused generation was retried or failure hidden: %T calls %d", err, calls.Load())
	}
	if !strings.Contains(logs.String(), "conn_reused=true") || !strings.Contains(logs.String(), "replayed=false") {
		t.Fatal("reuse evidence missing")
	}
}
