package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const modelIdleTimeout = 95 * time.Minute
const relayRequestHeader = "X-Rewind-Relay-Request"
const relayErrorHeader = "X-Rewind-Relay-Error"

type relayRequest struct {
	headers http.Header
	digest  string
}

// A single-use loopback hop retains host callback cancellation without exposing
// model tokens to the host's HTTP logger. See docs/rewind.md#connection-policy.
type modelRelay struct {
	mu       sync.Mutex
	requests map[string]relayRequest
	closed   bool
	server   *http.Server
	client   *http.Client
	url      string
	target   string
	idle     time.Duration
}

var relayMu sync.Mutex
var runningModelRelay *modelRelay

func getModelRelay() (*modelRelay, *problem) {
	relayMu.Lock()
	defer relayMu.Unlock()
	runtimeMu.Lock()
	stopped := stopping
	runtimeMu.Unlock()
	if stopped {
		return nil, fail(503, "rewind_stopping", "Rewind plugin is stopping")
	}
	if runningModelRelay == nil {
		relay, err := newModelRelay(newModelHTTPClient(), rewindOrigin+"/v1/responses", modelIdleTimeout)
		if err != nil {
			return nil, fail(503, "rewind_transport", "Cannot start Rewind's private model transport")
		}
		runningModelRelay = relay
	}
	return runningModelRelay, nil
}

func stopModelRelay() {
	relayMu.Lock()
	defer relayMu.Unlock()
	if runningModelRelay != nil {
		runningModelRelay.close()
		runningModelRelay = nil
	}
}

func newModelRelay(client *http.Client, target string, idle time.Duration) (*modelRelay, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &modelRelay{requests: make(map[string]relayRequest), client: client, target: target, idle: idle, url: "http://" + listener.Addr().String() + "/v1/responses"}
	r.server = &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: idle}
	go func() { _ = r.server.Serve(listener) }()
	return r, nil
}

func (r *modelRelay) authorize(headers http.Header, body []byte) (string, *problem) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return "", fail(503, "rewind_stopping", "Rewind plugin is stopping")
	}
	id := uuid()
	normalized := make(http.Header)
	for name, values := range headers {
		for _, value := range values {
			normalized.Add(name, value)
		}
	}
	r.requests[id] = relayRequest{headers: normalized, digest: digest(body)}
	return id, nil
}

func (r *modelRelay) revoke(id string) {
	r.mu.Lock()
	delete(r.requests, id)
	r.mu.Unlock()
}

func (r *modelRelay) close() {
	r.mu.Lock()
	r.closed = true
	clear(r.requests)
	r.mu.Unlock()
	_ = r.server.Close()
	r.client.CloseIdleConnections()
}

func relayFailure(w http.ResponseWriter, p *problem) {
	w.Header().Set(relayErrorHeader, "1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(p.HTTPStatus)
	_ = json.NewEncoder(w).Encode(envelope{Error: p})
}

func (r *modelRelay) ServeHTTP(w http.ResponseWriter, incoming *http.Request) {
	if incoming.Method != http.MethodPost || incoming.URL.Path != "/v1/responses" || incoming.URL.RawQuery != "" || incoming.URL.Fragment != "" {
		http.NotFound(w, incoming)
		return
	}
	id := incoming.Header.Get(relayRequestHeader)
	r.mu.Lock()
	entry, ok := r.requests[id]
	delete(r.requests, id)
	r.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithCancel(incoming.Context())
	defer cancel()
	timer := time.AfterFunc(r.idle, func() { cancel(); _ = incoming.Body.Close() })
	defer timer.Stop()
	raw, err := io.ReadAll(io.LimitReader(incoming.Body, (32<<20)+1))
	if err != nil || len(raw) > 32<<20 || digest(raw) != entry.digest {
		relayFailure(w, fail(400, "invalid_request_error", "Private Rewind request body failed validation"))
		return
	}
	var sent atomic.Bool
	trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			sent.Store(true)
		}
	}}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, r.target, bytes.NewReader(raw))
	if err != nil {
		relayFailure(w, fail(500, "rewind_transport", "Invalid Rewind model endpoint"))
		return
	}
	request.Header = entry.headers
	request.Header.Set("X-Rewind-Client-Request-Id", id)
	response, err := r.client.Do(request)
	if err != nil {
		p := fail(502, "transient_transport", "Rewind connection could not be established")
		if sent.Load() {
			p = unknownModelOutcome()
		}
		relayFailure(w, p)
		return
	}
	defer response.Body.Close()
	timer.Reset(r.idle)
	if response.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
		if readErr != nil || len(body) > 65536 {
			body = nil // A confirmed HTTP refusal takes precedence over delivery uncertainty.
		}
		relayFailure(w, upstreamProblem(response.StatusCode, response.Header, body))
		return
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		relayFailure(w, unknownModelOutcome())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	buffer := make([]byte, 32<<10)
	filter := secretFilter{secrets: [][]byte{[]byte(strings.TrimPrefix(entry.headers.Get("Authorization"), "DPoP ")), []byte(entry.headers.Get("DPoP"))}}
	write := func(data []byte) bool {
		if len(data) == 0 {
			return true
		}
		if _, err := w.Write(data); err != nil {
			return false
		}
		return http.NewResponseController(w).Flush() == nil
	}
	total := 0
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			timer.Reset(r.idle)
			total += n
			if total > 32<<20 {
				panic(http.ErrAbortHandler)
			}
			if !write(filter.push(buffer[:n], false)) {
				return
			}
		}
		if readErr == io.EOF {
			write(filter.push(nil, true))
			return
		}
		if readErr != nil {
			// Abort, rather than reporting clean EOF for a failed model stream.
			panic(http.ErrAbortHandler)
		}
	}
}
