package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const rewindOrigin = "https://rewind-api.apiwharf.com"
const appVersion = "1.0.6"

// The desktop session protocol rejects Linux's GOOS; this is a wire compatibility tag.
const clientPlatform = "darwin"

type credential struct {
	Type       string `json:"type"`
	APIKeyFile string `json:"api_key_file"`
	DeviceFile string `json:"device_file"`
	Prefix     string `json:"prefix"`
}

type jwk struct{ Kty, Crv, X, Y string }

func (j jwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y})
}

type session struct {
	Status      string `json:"status"`
	ModelToken  string `json:"model_token"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expires_at"`
	Thumbprint  string `json:"thumbprint"`
	AppVersion  string `json:"app_version"`
	PairingCode string `json:"pairing_code"`
}

type sessionClient struct {
	mu         sync.Mutex
	credential credential
	private    *ecdsa.PrivateKey
	public     jwk
	key        string
	session    session
	origin     string
	client     *http.Client
	now        func() time.Time
}

var clients sync.Map

func getClient(c credential) *sessionClient {
	key := c.APIKeyFile + "\x00" + c.DeviceFile
	v, _ := clients.LoadOrStore(key, &sessionClient{credential: c, origin: rewindOrigin, now: time.Now,
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	return v.(*sessionClient)
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func encode(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (c *sessionClient) device() *problem {
	if c.private != nil {
		return nil
	}
	raw, err := os.ReadFile(c.credential.DeviceFile)
	if os.IsNotExist(err) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return fail(500, "rewind_device", "Cannot create Rewind device key")
		}
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		raw, _ = json.Marshal(map[string]string{"pkcs8": base64.StdEncoding.EncodeToString(der)})
		if os.MkdirAll(filepath.Dir(c.credential.DeviceFile), 0700) != nil {
			return fail(500, "rewind_device", "Cannot create Rewind state directory")
		}
		// Link publishes a complete private key without replacing an existing device.
		tmp, e := os.CreateTemp(filepath.Dir(c.credential.DeviceFile), ".device-*")
		if e != nil {
			return fail(500, "rewind_device", "Cannot save Rewind device key")
		}
		defer os.Remove(tmp.Name())
		_, e = tmp.Write(raw)
		if e == nil {
			e = tmp.Sync()
		}
		closeErr := tmp.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return fail(500, "rewind_device", "Cannot save Rewind device key")
		}
		if e = os.Link(tmp.Name(), c.credential.DeviceFile); e != nil && !os.IsExist(e) {
			return fail(500, "rewind_device", "Cannot save Rewind device key")
		}
		raw, err = os.ReadFile(c.credential.DeviceFile)
	}
	info, e := os.Stat(c.credential.DeviceFile)
	if err != nil || e != nil || info.Mode().Perm()&0077 != 0 {
		return fail(500, "rewind_device", "Rewind device key must be readable only by its owner")
	}
	var stored struct {
		PKCS8 string `json:"pkcs8"`
	}
	if json.Unmarshal(raw, &stored) != nil {
		return fail(500, "rewind_device", "Invalid Rewind device key")
	}
	der, e := base64.StdEncoding.DecodeString(stored.PKCS8)
	if e != nil {
		return fail(500, "rewind_device", "Invalid Rewind device key")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(der)
	if e != nil {
		return fail(500, "rewind_device", "Invalid Rewind device key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return fail(500, "rewind_device", "Invalid Rewind device key")
	}
	c.private = key
	c.public = jwk{"EC", "P-256", base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
	return nil
}

func (c *sessionClient) proof(token, nonce, url, method string, body []byte) (string, *problem) {
	header := encode(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": c.public})
	claims := encode(map[string]any{"jti": uuid(), "iat": c.now().Unix(), "htm": method, "htu": url, "ath": digest([]byte(token)), "nonce": nonce, "rqh": digest(body), "upload_offset": "", "upload_final": ""})
	message := header + "." + claims
	hashed := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, c.private, hashed[:])
	if err != nil {
		return "", fail(500, "rewind_signing", "Rewind signing failed")
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func upstreamProblem(status int, headers http.Header, raw []byte) *problem {
	if status == 426 {
		return fail(426, "rewind_update_required", "Rewind requires a newer client protocol")
	}
	var v struct {
		Code  string `json:"code"`
		Error struct {
			Code string `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &v)
	code := strings.ToLower(v.Code + " " + v.Error.Code + " " + v.Error.Type)
	if status == 402 || strings.Contains(code, "insufficient_quota") || strings.Contains(code, "quota_exhausted") || strings.Contains(code, "insufficient_balance") {
		return fail(402, "insufficient_quota", "Rewind quota exhausted")
	}
	if status == 429 || strings.Contains(code, "rate_limit") {
		return fail(429, "rate_limit_exceeded", "Rewind rate limit exceeded")
	}
	if status == 401 || status == 403 {
		return fail(status, "rewind_auth_denied", "Rewind authorization failed; check key and device approval")
	}
	if status == 400 || status == 413 || status == 422 {
		return fail(status, "invalid_request_error", "Rewind rejected the request; check model parameters and input size")
	}
	return fail(502, "rewind_upstream", "Rewind upstream unavailable")
}

func (c *sessionClient) jsonRequest(path string, body []byte, headers http.Header, out any) *problem {
	req, err := http.NewRequest(http.MethodPost, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return fail(500, "rewind_auth", "Invalid Rewind endpoint")
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return fail(502, "rewind_auth_unavailable", "Rewind identity service unavailable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return fail(502, "rewind_auth_unavailable", "Invalid Rewind identity response")
	}
	if res.StatusCode != 200 {
		return upstreamProblem(res.StatusCode, res.Header, raw)
	}
	if json.Unmarshal(raw, out) != nil {
		return fail(502, "rewind_auth_unavailable", "Invalid Rewind identity response")
	}
	return nil
}

func (c *sessionClient) headers(url string, body []byte) (http.Header, *problem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := os.ReadFile(c.credential.APIKeyFile)
	key := strings.TrimSpace(string(raw))
	if err != nil || key == "" || strings.ContainsAny(key, " \t\r\n") {
		return nil, fail(503, "rewind_key_unavailable", "Rewind API key file unavailable")
	}
	if err := c.device(); err != nil {
		return nil, err
	}
	if key != c.key || c.session.ExpiresAt <= c.now().Unix()+30 {
		var challenge struct {
			Nonce string `json:"nonce"`
		}
		body, _ := json.Marshal(map[string]any{"jwk": c.public})
		if err := c.jsonRequest("/api/v1/rewind/challenge", body, nil, &challenge); err != nil {
			return nil, err
		}
		if len(challenge.Nonce) != 43 {
			return nil, fail(502, "rewind_auth_unavailable", "Invalid Rewind challenge")
		}
		body, _ = json.Marshal(map[string]string{"nonce": challenge.Nonce, "platform": clientPlatform, "app_version": appVersion})
		proof, e := c.proof(key, challenge.Nonce, c.origin+"/api/v1/rewind/sessions", "POST", body)
		if e != nil {
			return nil, e
		}
		var s session
		if e := c.jsonRequest("/api/v1/rewind/sessions", body, http.Header{"Authorization": {"Bearer " + key}, "Dpop": {proof}}, &s); e != nil {
			return nil, e
		}
		if s.Status == "pending" {
			return nil, fail(403, "rewind_device_approval_required", "Rewind device awaits administrator approval")
		}
		thumb, _ := json.Marshal(map[string]string{"crv": c.public.Crv, "kty": c.public.Kty, "x": c.public.X, "y": c.public.Y})
		if s.Status != "verified" || s.Thumbprint != digest(thumb) || s.AppVersion != appVersion || len(s.Nonce) != 43 || s.ExpiresAt <= c.now().Unix()+30 || s.ExpiresAt > c.now().Unix()+310 || len(s.ModelToken) < 100 || strings.ContainsAny(s.ModelToken, " \r\n\t") {
			return nil, fail(502, "rewind_auth_unavailable", "Invalid Rewind session")
		}
		c.key, c.session = key, s
	}
	proof, e := c.proof(c.session.ModelToken, c.session.Nonce, url, "POST", body)
	if e != nil {
		return nil, e
	}
	return http.Header{"Authorization": {"DPoP " + c.session.ModelToken}, "Dpop": {proof}, "Content-Type": {"application/json"}, "Accept": {"text/event-stream"}, "Accept-Encoding": {"identity"}}, nil
}

func (c *sessionClient) invalidate() { c.mu.Lock(); c.session = session{}; c.mu.Unlock() }
