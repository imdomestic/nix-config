package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func verifyProof(t *testing.T, proof, token, nonce, url string, body []byte) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT")
	}
	decode := func(s string) []byte {
		b, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var header struct {
		Alg, Typ string
		JWK      jwk
	}
	if json.Unmarshal(decode(parts[0]), &header) != nil || header.Alg != "ES256" || header.Typ != "dpop+jwt" {
		t.Fatal("invalid header")
	}
	var claims map[string]any
	if json.Unmarshal(decode(parts[1]), &claims) != nil {
		t.Fatal("invalid claims")
	}
	if claims["ath"] != digest([]byte(token)) || claims["nonce"] != nonce || claims["htu"] != url || claims["htm"] != "POST" || claims["rqh"] != digest(body) {
		t.Fatal("proof not bound to this exact request")
	}
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(decode(header.JWK.X)), Y: new(big.Int).SetBytes(decode(header.JWK.Y))}
	sig := decode(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("invalid ES256 signature")
	}
	return claims
}

func TestSessionProofRenewalAndConcurrentCalls(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	deviceFile := filepath.Join(dir, "device.json")
	if e := os.WriteFile(keyFile, []byte("test-api-key\n"), 0600); e != nil {
		t.Fatal(e)
	}
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	var exchanges atomic.Int64
	var public jwk
	var server *httptest.Server
	nonce := strings.Repeat("n", 43)
	token := strings.Repeat("t", 120)
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/api/v1/rewind/challenge":
			var v struct{ JWK jwk }
			_ = json.Unmarshal(raw, &v)
			public = v.JWK
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce})
		case "/api/v1/rewind/sessions":
			exchanges.Add(1)
			var login struct {
				Platform string `json:"platform"`
			}
			if json.Unmarshal(raw, &login) != nil || login.Platform != "darwin" {
				t.Error("unsupported Rewind session platform")
			}
			verifyProof(t, r.Header.Get("DPoP"), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), nonce, server.URL+r.URL.Path, raw)
			thumb, _ := json.Marshal(map[string]string{"crv": public.Crv, "kty": public.Kty, "x": public.X, "y": public.Y})
			_ = json.NewEncoder(w).Encode(session{Status: "verified", ModelToken: token, Nonce: nonce, ExpiresAt: clock.Load() + 300, Thumbprint: digest(thumb), AppVersion: appVersion})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := &sessionClient{credential: credential{APIKeyFile: keyFile, DeviceFile: deviceFile}, origin: server.URL, client: server.Client(), now: func() time.Time { return time.Unix(clock.Load(), 0) }}
	body := []byte(`{"model":"gpt-6-astra","input":[{"type":"function_call_output","call_id":"call_1","output":"42"}],"reasoning":{"effort":"xhigh"}}`)
	var wg sync.WaitGroup
	var ids sync.Map
	for range 12 {
		wg.Go(func() {
			h, e := c.headers(rewindOrigin+"/v1/responses", body)
			if e != nil {
				t.Error(e)
				return
			}
			claims := verifyProof(t, h.Get("DPoP"), token, nonce, rewindOrigin+"/v1/responses", body)
			if _, loaded := ids.LoadOrStore(claims["jti"], true); loaded {
				t.Error("reused request proof")
			}
		})
	}
	wg.Wait()
	if exchanges.Load() != 1 {
		t.Fatalf("concurrent renewal count %d", exchanges.Load())
	}
	clock.Add(271)
	if _, e := c.headers(rewindOrigin+"/v1/responses", body); e != nil {
		t.Fatal(e)
	}
	if exchanges.Load() != 2 {
		t.Fatal("expiring token was not renewed")
	}
	if e := os.WriteFile(keyFile, []byte("replacement-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := c.headers(rewindOrigin+"/v1/responses", body); e != nil {
		t.Fatal(e)
	}
	if exchanges.Load() != 3 {
		t.Fatal("rotated key reused old session")
	}
	restarted := &sessionClient{credential: c.credential, origin: server.URL, client: server.Client(), now: c.now}
	if _, e := restarted.headers(rewindOrigin+"/v1/responses", body); e != nil {
		t.Fatal(e)
	}
	if restarted.public != c.public {
		t.Fatal("device identity changed across restart")
	}
}

func TestPendingDeviceAndErrorRedaction(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	_ = os.WriteFile(keyFile, []byte("test-api-key"), 0600)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "challenge") {
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": strings.Repeat("n", 43)})
			return
		}
		_ = json.NewEncoder(w).Encode(session{Status: "pending", PairingCode: "123456"})
	}))
	defer server.Close()
	c := &sessionClient{credential: credential{APIKeyFile: keyFile, DeviceFile: filepath.Join(dir, "device.json")}, origin: server.URL, client: server.Client(), now: time.Now}
	_, e := c.headers(rewindOrigin+"/v1/responses", nil)
	if e == nil || e.HTTPStatus != 403 || e.Code != "rewind_device_approval_required" {
		t.Fatalf("pending device was not respected: %v", e)
	}
	for _, status := range []int{400, 401, 402, 403, 413, 422, 426, 429, 500} {
		p := upstreamProblem(status, nil, []byte(`{"error":{"message":"test-api-key private token"}}`))
		if strings.Contains(p.Message, "private") || strings.Contains(p.Message, "test-api-key") {
			t.Fatal("upstream error leaked credentials")
		}
		if status < 500 && p.HTTPStatus != status {
			t.Fatalf("lost HTTP status %d", status)
		}
	}
}
