package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeTestDevice(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"pkcs8": base64.StdEncoding.EncodeToString(der)})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func testBalanceFiles(t *testing.T) balanceConfig {
	t.Helper()
	dir := t.TempDir()
	config := balanceConfig{
		ListenAddress: "127.0.0.1",
		Port:          8318,
		ClientKeyFile: filepath.Join(dir, "client-key"),
		APIKeyFile:    filepath.Join(dir, "api-key"),
		DeviceFile:    filepath.Join(dir, "device.json"),
	}
	if err := os.WriteFile(config.ClientKeyFile, []byte("client-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.APIKeyFile, []byte("api-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeTestDevice(t, config.DeviceFile)
	return config
}

func validBalanceJSON(amount string) []byte {
	return []byte(`{"schema":"rewind.balance.v1","currency":"USD","available_usd":"` + amount + `","exhausted":false,"as_of":"2026-11-04T12:34:56Z"}`)
}

func balanceRequest(method, target, key string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	return req
}

func TestBalanceAuthRotationAndRequestRejection(t *testing.T) {
	config := testBalanceFiles(t)
	service := newBalanceService(config)
	defer service.stop()
	service.fetch = func(context.Context, balanceConfig) ([]byte, *problem) { return validBalanceJSON("12.50"), nil }

	assertStatus := func(want int, req *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		service.ServeHTTP(response, req)
		if response.Code != want {
			t.Fatalf("status %d, want %d: %s", response.Code, want, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "secret") {
			t.Fatal("response leaked a key")
		}
		return response
	}
	assertStatus(http.StatusUnauthorized, balanceRequest(http.MethodGet, balancePath, "", nil))
	assertStatus(http.StatusUnauthorized, balanceRequest(http.MethodGet, balancePath, "wrong", nil))
	good := assertStatus(http.StatusOK, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if good.Body.String() != string(validBalanceJSON("12.50")) {
		t.Fatalf("unexpected balance: %s", good.Body.String())
	}
	if err := os.WriteFile(config.ClientKeyFile, []byte("rotated-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	assertStatus(http.StatusUnauthorized, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	assertStatus(http.StatusOK, balanceRequest(http.MethodGet, balancePath, "rotated-secret", nil))

	assertStatus(http.StatusNotFound, balanceRequest(http.MethodGet, "/", "rotated-secret", nil))
	assertStatus(http.StatusNotFound, balanceRequest(http.MethodGet, balancePath+"?x=1", "rotated-secret", nil))
	assertStatus(http.StatusMethodNotAllowed, balanceRequest(http.MethodOptions, balancePath, "rotated-secret", nil))
	assertStatus(http.StatusMethodNotAllowed, balanceRequest(http.MethodPost, balancePath, "rotated-secret", nil))
	assertStatus(http.StatusBadRequest, balanceRequest(http.MethodGet, balancePath, "rotated-secret", strings.NewReader("x")))

	duplicate := balanceRequest(http.MethodGet, balancePath, "rotated-secret", nil)
	duplicate.Header.Add("Authorization", "Bearer rotated-secret")
	assertStatus(http.StatusUnauthorized, duplicate)
}

func TestBalanceStopWaitsForFetchExit(t *testing.T) {
	config := testBalanceFiles(t)
	service := newBalanceService(config)
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	service.fetch = func(ctx context.Context, _ balanceConfig) ([]byte, *problem) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, fail(503, "canceled", "Balance canceled")
	}
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		service.ServeHTTP(httptest.NewRecorder(), balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	}()
	<-started
	stopped := make(chan struct{})
	go func() { service.stop(); close(stopped) }()
	<-canceled
	select {
	case <-stopped:
		t.Fatal("plugin shutdown returned before its balance fetch exited")
	default:
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("balance worker did not finish shutdown")
	}
	<-requestDone
	response := httptest.NewRecorder()
	service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("stopped balance service accepted another request")
	}
}

func TestBalanceNormalizationAndRedaction(t *testing.T) {
	valid := []byte(`{"schema":"rewind.quota.v1","currency":"USD","available_usd":"001.2500","exhausted":false,"as_of":"2026-11-04T12:34:56.123Z","token":"private"}`)
	normalized, err := normalizeBalance(valid)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"rewind.balance.v1","currency":"USD","available_usd":"001.2500","exhausted":false,"as_of":"2026-11-04T12:34:56.123Z"}`
	if string(normalized) != want || bytes.Contains(normalized, []byte("private")) {
		t.Fatalf("unexpected normalized response: %s", normalized)
	}
	for _, raw := range []string{
		`{"schema":"other","currency":"USD","available_usd":"1","exhausted":false,"as_of":"2026-11-04T12:34:56Z"}`,
		`{"schema":"rewind.quota.v1","currency":"EUR","available_usd":"1","exhausted":false,"as_of":"2026-11-04T12:34:56Z"}`,
		`{"schema":"rewind.quota.v1","currency":"USD","available_usd":"-1","exhausted":false,"as_of":"2026-11-04T12:34:56Z"}`,
		`{"schema":"rewind.quota.v1","currency":"USD","available_usd":"0.000","exhausted":false,"as_of":"2026-11-04T12:34:56Z"}`,
		`{"schema":"rewind.quota.v1","currency":"USD","available_usd":null,"exhausted":true,"as_of":"2026-11-04T12:34:56Z"}`,
		`{"schema":"rewind.quota.v1","currency":"USD","available_usd":"1","exhausted":false,"as_of":"not-a-date"}`,
	} {
		if output, err := normalizeBalance([]byte(raw)); err == nil {
			t.Fatalf("invalid quota accepted: %s", output)
		}
	}
	zero, err := normalizeBalance([]byte(`{"schema":"rewind.quota.v1","currency":"USD","available_usd":"0.000","exhausted":true,"as_of":"2026-11-04T12:34:56Z"}`))
	if err != nil || !bytes.Contains(zero, []byte(`"exhausted":true`)) {
		t.Fatalf("valid exhausted quota rejected: %s, %v", zero, err)
	}
	nullAmount, err := normalizeBalance([]byte(`{"schema":"rewind.quota.v1","currency":"USD","available_usd":null,"exhausted":false,"as_of":"2026-11-04T12:34:56Z"}`))
	if err != nil || !bytes.Contains(nullAmount, []byte(`"available_usd":null`)) {
		t.Fatalf("valid unknown quota rejected: %s, %v", nullAmount, err)
	}
}

func TestBalanceCacheCoalescingBackoffAndIdentityRotation(t *testing.T) {
	config := testBalanceFiles(t)
	service := newBalanceService(config)
	defer service.stop()
	var nowMu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	service.now = func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	advance := func(d time.Duration) { nowMu.Lock(); now = now.Add(d); nowMu.Unlock() }
	var calls atomic.Int64
	gate := make(chan struct{})
	service.fetch = func(context.Context, balanceConfig) ([]byte, *problem) {
		call := calls.Add(1)
		if call == 1 {
			<-gate
		}
		if call == 3 || call == 4 {
			return nil, fail(502, "upstream", "private upstream error")
		}
		return validBalanceJSON("9.00"), nil
	}

	const concurrent = 12
	var wg sync.WaitGroup
	statuses := make(chan int, concurrent)
	for range concurrent {
		wg.Go(func() {
			response := httptest.NewRecorder()
			service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
			statuses <- response.Code
		})
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(gate)
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("coalesced request failed: %d", status)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d, want 1", calls.Load())
	}

	response := httptest.NewRecorder()
	service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatal("fresh cache was not used")
	}
	if err := os.WriteFile(config.APIKeyFile, []byte("rotated-api-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if response.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatal("old identity cache survived API key rotation")
	}

	advance(61 * time.Second)
	response = httptest.NewRecorder()
	service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 3 || strings.Contains(response.Body.String(), "private") {
		t.Fatal("failed refresh was not sanitized")
	}
	response = httptest.NewRecorder()
	service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 3 {
		t.Fatal("failure backoff did not suppress polling")
	}
	advance(time.Second)
	response = httptest.NewRecorder()
	service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 4 {
		t.Fatal("backoff did not permit a bounded retry")
	}
}

func TestBalanceGETProofAndSharedRenewal(t *testing.T) {
	config := testBalanceFiles(t)
	var exchanges atomic.Int64
	var public jwk
	nonce := strings.Repeat("n", 43)
	token := strings.Repeat("t", 120)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/rewind/challenge":
			var request struct{ JWK jwk }
			_ = json.Unmarshal(raw, &request)
			public = request.JWK
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
		case "/api/v1/rewind/sessions":
			exchanges.Add(1)
			verifyProof(t, r.Header.Get("DPoP"), "api-secret", nonce, http.MethodPost, server.URL+r.URL.Path, raw)
			thumb, _ := json.Marshal(map[string]string{"crv": public.Crv, "kty": public.Kty, "x": public.X, "y": public.Y})
			_ = json.NewEncoder(w).Encode(session{Status: "verified", ModelToken: token, Nonce: nonce, ExpiresAt: time.Now().Unix() + 300, Thumbprint: digest(thumb), AppVersion: appVersion})
		case balanceUsagePath:
			if r.Method != http.MethodGet || len(raw) != 0 || r.Header.Get("Authorization") != "DPoP "+token {
				t.Error("usage request contract changed")
			}
			verifyProof(t, r.Header.Get("DPoP"), token, nonce, http.MethodGet, server.URL+r.URL.Path, nil)
			_, _ = io.WriteString(w, `{"schema":"rewind.quota.v1","currency":"USD","available_usd":"4.25","exhausted":false,"as_of":"2026-11-04T12:34:56Z","secret":"do-not-return"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := &sessionClient{credential: credential{APIKeyFile: config.APIKeyFile, DeviceFile: config.DeviceFile}, origin: server.URL, client: server.Client(), now: time.Now}
	mapKey := config.APIKeyFile + "\x00" + config.DeviceFile
	clients.Store(mapKey, client)
	defer clients.Delete(mapKey)

	if _, err := client.headers(rewindOrigin+"/v1/responses", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	raw, problem := fetchBalance(context.Background(), config)
	if problem != nil {
		t.Fatal(problem)
	}
	if exchanges.Load() != 1 {
		t.Fatalf("balance did not share the existing renewal: %d", exchanges.Load())
	}
	if string(raw) != `{"schema":"rewind.balance.v1","currency":"USD","available_usd":"4.25","exhausted":false,"as_of":"2026-11-04T12:34:56Z"}` {
		t.Fatalf("unexpected balance response: %s", raw)
	}
}

func TestBalanceOversizeErrorsCancellationAndDisabledRegistration(t *testing.T) {
	config := testBalanceFiles(t)
	client := &sessionClient{credential: credential{APIKeyFile: config.APIKeyFile, DeviceFile: config.DeviceFile}, now: time.Now}
	if problem := client.device(false); problem != nil {
		t.Fatal(problem)
	}
	client.key = "api-secret"
	client.session = session{Status: "verified", ModelToken: strings.Repeat("t", 120), Nonce: strings.Repeat("n", 43), ExpiresAt: time.Now().Unix() + 300, AppVersion: appVersion}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(append(bytes.Repeat([]byte("x"), (64<<10)+1), []byte(" private-token")...))
	}))
	defer server.Close()
	client.origin, client.client = server.URL, server.Client()
	mapKey := config.APIKeyFile + "\x00" + config.DeviceFile
	clients.Store(mapKey, client)
	defer clients.Delete(mapKey)
	if _, problem := fetchBalance(context.Background(), config); problem == nil || strings.Contains(problem.Message, "private-token") {
		t.Fatal("oversized upstream error was not sanitized")
	}

	service := newBalanceService(config)
	started := make(chan struct{})
	service.fetch = func(ctx context.Context, _ balanceConfig) ([]byte, *problem) {
		close(started)
		<-ctx.Done()
		return nil, fail(502, "canceled", "canceled")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		response := httptest.NewRecorder()
		service.ServeHTTP(response, balanceRequest(http.MethodGet, balancePath, "client-secret", nil))
	}()
	<-started
	service.stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("balance fetch ignored lifetime cancellation")
	}

	old, present := os.LookupEnv(balanceConfigEnv)
	defer func() {
		if present {
			_ = os.Setenv(balanceConfigEnv, old)
		} else {
			_ = os.Unsetenv(balanceConfigEnv)
		}
	}()
	_ = os.Unsetenv(balanceConfigEnv)
	stopBalanceListener()
	if problem := configureBalance(); problem != nil || currentBalanceListener != nil {
		t.Fatalf("disabled registration started a listener: %v", problem)
	}
}

func TestBalanceRegistrationStartsNoUpstreamAndStops(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "balance.json")
	raw, _ := json.Marshal(balanceConfig{
		ListenAddress: "127.0.0.1",
		Port:          port,
		ClientKeyFile: filepath.Join(dir, "missing-client-key"),
		APIKeyFile:    filepath.Join(dir, "missing-api-key"),
		DeviceFile:    filepath.Join(dir, "missing-device.json"),
	})
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	old, present := os.LookupEnv(balanceConfigEnv)
	defer func() {
		stopBalanceListener()
		if present {
			_ = os.Setenv(balanceConfigEnv, old)
		} else {
			_ = os.Unsetenv(balanceConfigEnv)
		}
	}()
	if err := os.Setenv(balanceConfigEnv, configPath); err != nil {
		t.Fatal(err)
	}
	stopBalanceListener()
	if problem := configureBalance(); problem != nil {
		t.Fatal(problem)
	}
	first := currentBalanceListener
	if first == nil {
		t.Fatal("registration did not start the configured listener")
	}
	if problem := configureBalance(); problem != nil || currentBalanceListener != first {
		t.Fatalf("idempotent registration replaced the listener: %v", problem)
	}
	response, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + balancePath)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request without a key returned %d", response.StatusCode)
	}
	stopBalanceListener()
	client := &net.Dialer{Timeout: 100 * time.Millisecond}
	connection, err := client.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err == nil {
		_ = connection.Close()
		t.Fatal("listener still accepted connections after shutdown")
	}
}

func TestBalanceStopClosesPartialHeaderConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service := newBalanceService(testBalanceFiles(t))
	server := &http.Server{Handler: service, ReadHeaderTimeout: 5 * time.Second}
	runtime := &balanceListener{service: service, server: server, listener: listener, done: make(chan struct{})}
	accepted := make(chan struct{})
	server.ConnState = func(connection net.Conn, state http.ConnState) {
		runtime.connectionState(connection, state)
		if state == http.StateNew {
			close(accepted)
		}
	}
	go func() { defer close(runtime.done); _ = server.Serve(listener) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		runtime.stop(50 * time.Millisecond)
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = io.WriteString(connection, "GET /rewind/balance HTTP/1.1\r\nHost:")
	<-accepted
	started := time.Now()
	runtime.stop(50 * time.Millisecond)
	if time.Since(started) > time.Second {
		t.Fatal("shutdown waited for the five-second partial-header timeout")
	}
	_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("partial-header connection remained open after shutdown")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("shutdown did not force-close the accepted connection")
	}
}

func TestBalanceConfigRejectsPublicAndWildcardAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::", "8.8.8.8", "2001:4860:4860::8888"} {
		if _, err := safeListenAddress(address); err == nil {
			t.Fatalf("unsafe address accepted: %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "::1", "100.64.0.1", "fd7a:115c:a1e0::1"} {
		if _, err := safeListenAddress(address); err != nil {
			t.Fatalf("safe address rejected: %s: %v", address, err)
		}
	}
}
