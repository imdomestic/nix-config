package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func relayForTest(t *testing.T, client *http.Client, target string, idle time.Duration) *modelRelay {
	t.Helper()
	r, err := newModelRelay(client, target, idle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	return r
}

func authorizedRelayRequest(t *testing.T, r *modelRelay, body []byte) *http.Request {
	t.Helper()
	id, p := r.authorize(http.Header{"Authorization": {"DPoP private-model-token"}, "DPoP": {"private-proof"}, "Accept": {"text/event-stream"}, "Content-Type": {"application/json"}}, body)
	if p != nil {
		t.Fatal(p)
	}
	request, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(relayRequestHeader, id)
	return request
}

func relayProblemForTest(t *testing.T, response *http.Response) *problem {
	t.Helper()
	defer response.Body.Close()
	var env envelope
	if err := json.NewDecoder(response.Body).Decode(&env); err != nil || env.Error == nil || response.Header.Get(relayErrorHeader) != "1" {
		t.Fatalf("invalid private relay error, status %d: %v", response.StatusCode, err)
	}
	return env.Error
}

func TestModelRelayOneUseBodyBindingAndPinnedEndpoint(t *testing.T) {
	var calls atomic.Int32
	body := []byte(`{"model":"gpt-6-luna","input":"hello","stream":true}`)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "DPoP private-model-token" || request.Header.Get("DPoP") != "private-proof" || request.Header.Get(relayRequestHeader) != "" || !requestIDPattern.MatchString(request.Header.Get("X-Rewind-Client-Request-Id")) {
			t.Error("model endpoint, proof or relay isolation changed")
		}
		raw, _ := io.ReadAll(request.Body)
		if !bytes.Equal(raw, body) {
			t.Error("signed request body changed")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")
	}))
	defer upstream.Close()
	r := relayForTest(t, upstream.Client(), upstream.URL+"/v1/responses", time.Second)
	request := authorizedRelayRequest(t, r, body)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, p := readSSE(response.Body, nil); p != nil {
		t.Fatal(p)
	}
	response.Body.Close()
	request = request.Clone(context.Background())
	request.Body = io.NopCloser(bytes.NewReader(body))
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 || calls.Load() != 1 {
		t.Fatal("single-use relay authorization was replayed")
	}
	request = authorizedRelayRequest(t, r, body)
	request.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", len(body))))
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if p := relayProblemForTest(t, response); p.HTTPStatus != 400 || calls.Load() != 1 {
		t.Fatal("modified signed body was sent upstream")
	}
	for _, suffix := range []string{"?url=https://elsewhere.invalid", "/other"} {
		request = authorizedRelayRequest(t, r, body)
		request.URL, _ = request.URL.Parse(r.url + suffix)
		response, err = http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 || calls.Load() != 1 {
			t.Fatal("relay exposed arbitrary forwarding")
		}
		r.revoke(request.Header.Get(relayRequestHeader))
	}
	r.close()
	if _, p := r.authorize(nil, nil); p == nil {
		t.Fatal("closed relay accepted another authorization")
	}
}

func TestModelRelayCancellationPropagatesBeforeResponseHeaders(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		close(started)
		<-request.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	r := relayForTest(t, upstream.Client(), upstream.URL+"/v1/responses", time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := authorizedRelayRequest(t, r, []byte(`{}`)).WithContext(ctx)
	done := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("model request did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("downstream cancellation did not close the silent upstream request")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation: %v", err)
	}
}

func TestModelRelayDeliveryClassificationAndNoReplay(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "after-write"}[sent], func(t *testing.T) {
			var calls atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls.Add(1)
				if sent {
					httptrace.ContextClientTrace(request.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				}
				return nil, errors.New("private server detail")
			})}
			r := relayForTest(t, client, "https://rewind.invalid/v1/responses", time.Second)
			response, err := http.DefaultClient.Do(authorizedRelayRequest(t, r, []byte(`{}`)))
			if err != nil {
				t.Fatal(err)
			}
			p := relayProblemForTest(t, response)
			if calls.Load() != 1 || strings.Contains(p.Message, "private") {
				t.Fatal("model request was replayed or leaked a transport error")
			}
			if sent {
				if p.Code != "REWIND_REQUEST_OUTCOME_UNKNOWN" || p.HTTPStatus != 503 || routingProblem(p).Code != "stream_truncated" {
					t.Fatal("uncertain execution remained eligible for gateway replay")
				}
			} else if p.Code != "transient_transport" || p.HTTPStatus != 502 {
				t.Fatal("pre-HTTP failure incorrectly reported possible execution")
			}
		})
	}
}

func TestModelRelaySilenceTimeoutAndKnownRefusal(t *testing.T) {
	if modelIdleTimeout != 95*time.Minute {
		t.Fatal("model silence deadline differs from official 1.1.7")
	}
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		httptrace.ContextClientTrace(request.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	r := relayForTest(t, client, "https://rewind.invalid/v1/responses", 20*time.Millisecond)
	response, err := http.DefaultClient.Do(authorizedRelayRequest(t, r, []byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	if p := relayProblemForTest(t, response); p.Code != "REWIND_REQUEST_OUTCOME_UNKNOWN" || calls.Load() != 1 {
		t.Fatal("silent accepted request was replayed")
	}
	for _, status := range []int{401, 403, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(errorReader{})}, nil
			})}
			r := relayForTest(t, client, "https://rewind.invalid/v1/responses", time.Second)
			response, err := http.DefaultClient.Do(authorizedRelayRequest(t, r, []byte(`{}`)))
			if err != nil {
				t.Fatal(err)
			}
			p := relayProblemForTest(t, response)
			if p.HTTPStatus != status || p.Code == "REWIND_REQUEST_OUTCOME_UNKNOWN" {
				t.Fatalf("confirmed HTTP refusal lost precedence: %+v", p)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("partial private error") }

func TestNativeModelRelayProofAndCredentialRedaction(t *testing.T) {
	cert, roots := modelTestCertificate(t, "model.test")
	token, nonce := strings.Repeat("t", 120), strings.Repeat("n", 43)
	body := []byte(`{"model":"gpt-6-luna","input":"hello","stream":true,"store":false}`)
	var target string
	server := modelTestHTTPServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		verifyProof(t, request.Header.Get("DPoP"), token, nonce, http.MethodPost, target, raw)
		if !bytes.Equal(raw, body) || request.ProtoMajor != 1 || request.URL.Path != "/v1/responses" {
			t.Error("native transport altered the signed request")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		text, _ := json.Marshal(token + " / " + request.Header.Get("DPoP"))
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"text\":"+string(text)+"}}\n\n")
	}))
	target = "https://model.test/v1/responses"
	client := newModelHTTPClient()
	connector := modelTestConnector(roots)
	connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return modelTestIPs[1:], nil }
	connector.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	modelTestInstallConnector(client, connector)
	r := relayForTest(t, client, target, time.Second)
	device := &sessionClient{credential: credential{DeviceFile: filepath.Join(t.TempDir(), "device.json")}, now: time.Now}
	if p := device.device(true); p != nil {
		t.Fatal(p)
	}
	proof, p := device.proof(token, nonce, target, http.MethodPost, body)
	if p != nil {
		t.Fatal(p)
	}
	id, p := r.authorize(http.Header{"Authorization": {"DPoP " + token}, "DPoP": {proof}}, body)
	if p != nil {
		t.Fatal(p)
	}
	request, _ := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(body))
	request.Header.Set(relayRequestHeader, id)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	output, p := readSSE(response.Body, nil)
	if p != nil || string(output) != `{"text":"[REDACTED] / [REDACTED]"}` {
		t.Fatalf("native relay failed or exposed a credential: %s, %v", output, p)
	}
}

func TestModelRelayTruncatedStreamAndShutdown(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
	}))
	defer upstream.Close()
	r := relayForTest(t, upstream.Client(), upstream.URL, time.Second)
	response, err := http.DefaultClient.Do(authorizedRelayRequest(t, r, []byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, p := readSSE(response.Body, nil); p == nil || p.Code != "REWIND_REQUEST_OUTCOME_UNKNOWN" || routingProblem(p).Code != "stream_truncated" {
		t.Fatalf("incomplete accepted stream can be replayed: %v", p)
	}
}
