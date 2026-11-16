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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fakeAccess = "test-access-not-a-real-token"
const fakeRefresh = "test-refresh-not-a-real-token"
const fakeCode = "test-authorization-code"
const oauthClientID = "test-installed-client-id"
const oauthClientSecret = "test-installed-client-secret"

func testOAuth(t *testing.T, handler http.HandlerFunc) *oauthClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &oauthClient{client: server.Client(), authEndpoint: "https://accounts.example.test/authorize", tokenEndpoint: server.URL + "/token", userInfoEndpoint: server.URL + "/userinfo", clientID: oauthClientID, clientSecret: oauthClientSecret}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeOwnFixture(t *testing.T, path string, token ownToken) {
	t.Helper()
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := openPrivateCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.root.Close()
	if err := file.write(token, true, nil); err != nil {
		t.Fatal(err)
	}
}

func expiredOwnToken() ownToken {
	return ownToken{fakeAccess, fakeRefresh, "Bearer", time.Now().Add(-time.Hour)}
}

// Captures output without races while the test drives the loopback callback.
type loginOutput struct {
	mu   sync.Mutex
	data bytes.Buffer
	url  chan string
	once sync.Once
}

func newLoginOutput() *loginOutput { return &loginOutput{url: make(chan string, 1)} }
func (o *loginOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.data.Write(p)
	for _, line := range strings.Split(o.data.String(), "\n") {
		if strings.HasPrefix(line, "https://accounts.example.test/") {
			o.once.Do(func() { o.url <- line })
		}
	}
	return n, err
}
func (o *loginOutput) text() string { o.mu.Lock(); defer o.mu.Unlock(); return o.data.String() }

func awaitLoginURL(t *testing.T, out *loginOutput) *url.URL {
	t.Helper()
	select {
	case raw := <-out.url:
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal("invalid authorization URL")
		}
		return u
	case <-time.After(5 * time.Second):
		t.Fatal("login did not publish a URL")
		return nil
	}
}

func sendCallback(t *testing.T, auth *url.URL, q url.Values) int {
	t.Helper()
	u, err := url.Parse(auth.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal("invalid redirect URI")
	}
	u.Host = net.JoinHostPort("127.0.0.1", u.Port())
	u.RawQuery = q.Encode()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatal("callback request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, secret := range []string{fakeAccess, fakeRefresh, fakeCode} {
		if bytes.Contains(body, []byte(secret)) {
			t.Error("callback exposed a credential")
		}
	}
	return resp.StatusCode
}

func awaitLoginResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("login did not terminate")
		return errLogin
	}
}

func assertNoSecrets(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{fakeAccess, fakeRefresh, fakeCode, oauthClientSecret} {
		if strings.Contains(text, secret) {
			t.Fatal("credential leaked in diagnostic output")
		}
	}
}

func TestRuntimeOAuthClientConfiguration(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "client.json")
	data, _ := json.Marshal(oauthClientMetadata{ClientID: oauthClientID, ClientSecret: oauthClientSecret})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	o, err := loadOAuthClient(path)
	if err != nil || o.clientID != oauthClientID || o.clientSecret != oauthClientSecret {
		t.Fatal("private client configuration was not loaded")
	}
	_ = os.Chmod(path, 0644)
	if _, err := loadOAuthClient(path); err == nil {
		t.Fatal("public client file was accepted")
	}
	_ = os.Chmod(path, 0600)
	_ = os.WriteFile(path, []byte(`{"client_id":"bad\nheader","client_secret":"private"}`), 0600)
	if _, err := loadOAuthClient(path); err == nil {
		t.Fatal("invalid client configuration was accepted")
	}
}

func TestOAuthPKCEAndState(t *testing.T) {
	if pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal("RFC7636 S256 vector failed")
	}
	state, err := randomOAuthValue()
	if err != nil || len(state) != 43 {
		t.Fatal("invalid random state")
	}
	other, err := randomOAuthValue()
	if err != nil || state == other {
		t.Fatal("state reused")
	}
	verifier, _ := randomOAuthValue()
	o := newOAuthClient(oauthClientMetadata{ClientID: oauthClientID, ClientSecret: oauthClientSecret})
	u, err := url.Parse(o.authURL(state, verifier, "http://localhost:51121/oauth-callback"))
	if err != nil {
		t.Fatal("invalid authorization URL")
	}
	q := u.Query()
	if q.Get("state") != state || q.Get("code_challenge") != pkceChallenge(verifier) || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "select_account consent" || q.Get("access_type") != "offline" || q.Get("scope") != oauthScopes || q.Get("client_id") != oauthClientID {
		t.Fatal("OAuth authorization parameters incorrect")
	}
	assertNoSecrets(t, u.String())
	if o.tokenEndpoint != "https://oauth2.googleapis.com/token" || o.userInfoEndpoint != "https://www.googleapis.com/oauth2/v2/userinfo?alt=json" {
		t.Fatal("production endpoints changed")
	}
}

func TestLoginCallbacksAndExchange(t *testing.T) {
	var exchanges, userinfos atomic.Int32
	var auth *url.URL
	// The callback handler sends through result before tokens exchange; endpoint
	// expectations cross this channel to avoid test-owned pointer races.
	expect := make(chan *url.URL, 1)
	o := testOAuth(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			exchanges.Add(1)
			u := <-expect
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != fakeCode || r.Form.Get("redirect_uri") != u.Query().Get("redirect_uri") || pkceChallenge(r.Form.Get("code_verifier")) != u.Query().Get("code_challenge") || r.Form.Get("client_id") != oauthClientID || r.Form.Get("client_secret") != oauthClientSecret {
				t.Error("exchange parameters incorrect")
			}
			_, _ = io.WriteString(w, `{"access_token":"`+fakeAccess+`","refresh_token":"`+fakeRefresh+`","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			userinfos.Add(1)
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+fakeAccess {
				t.Error("userinfo request incorrect")
			}
			_, _ = io.WriteString(w, `{"email":"login-test@example.invalid","verified_email":true}`)
		default:
			t.Error("login called non-auth endpoint")
			w.WriteHeader(404)
		}
	})
	path := filepath.Join(privateTempDir(t), "own.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := newLoginOutput()
	result := make(chan error, 1)
	go func() { result <- o.login(ctx, path, 0, false, out) }()
	auth = awaitLoginURL(t, out)
	state := auth.Query().Get("state")
	for _, q := range []url.Values{
		{"state": {"wrong"}, "code": {fakeCode}},
		{"code": {fakeCode}},
		{"state": {state, state}, "code": {fakeCode}},
		{"state": {state}},
		{"state": {state}, "code": {fakeCode, fakeCode}},
		{"state": {state}, "code": {fakeCode}, "error": {"denied"}},
	} {
		if sendCallback(t, auth, q) != 400 {
			t.Fatal("bad callback accepted")
		}
		select {
		case <-result:
			t.Fatal("bad callback terminated login")
		default:
		}
		if exchanges.Load() != 0 {
			t.Fatal("bad callback exchanged a code")
		}
	}
	expect <- auth
	before := time.Now()
	if sendCallback(t, auth, url.Values{"state": {state}, "code": {fakeCode}}) != 200 {
		t.Fatal("valid callback rejected")
	}
	if err := awaitLoginResult(t, result); err != nil {
		t.Fatal(err)
	}
	if exchanges.Load() != 1 || userinfos.Load() != 1 {
		t.Fatal("login must only exchange and fetch userinfo once")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := decodeOwnToken(data)
	if err != nil || token.AccessToken != fakeAccess || token.RefreshToken != fakeRefresh || token.Expiry.Before(before.Add(3599*time.Second)) || token.Expiry.After(time.Now().Add(3601*time.Second)) {
		t.Fatal("stored token or expiry incorrect")
	}
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	if len(fields) != 4 || bytes.Contains(data, []byte("example.invalid")) {
		t.Fatal("saved identity or unexpected metadata")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("login file not 0600")
	}
	assertNoSecrets(t, out.text())
	if !strings.Contains(out.text(), "login-test@example.invalid") {
		t.Fatal("account selection not confirmed")
	}
}

func TestOAuthInvalidResponses(t *testing.T) {
	cases := []string{
		`null`, `not-json`, `{"access_token":"` + fakeAccess + `","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"bad\nheader","refresh_token":"` + fakeRefresh + `","token_type":"Bearer","expires_in":3600}`,
		`{"access_token":"` + fakeAccess + `","refresh_token":"` + fakeRefresh + `","token_type":"Basic","expires_in":3600}`,
		`{"access_token":"` + fakeAccess + `","refresh_token":"` + fakeRefresh + `","token_type":"Bearer","expires_in":0}`,
		`{"access_token":"` + fakeAccess + `","refresh_token":"` + fakeRefresh + `","token_type":"Bearer","expires_in":60}`,
		`{"access_token":"` + fakeAccess + `","refresh_token":"` + fakeRefresh + `","token_type":"Bearer","expires_in":9223372036854775807}`,
		`{"access_token":"` + fakeAccess + `","refresh_token":"` + fakeRefresh + `","token_type":"Bearer","expires_in":3600} {}`,
	}
	for i, body := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			o := testOAuth(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
			if _, err := o.tokens(context.Background(), url.Values{}, ""); !errors.Is(err, errOAuth) {
				t.Fatal("invalid token response accepted")
			}
		})
	}
	for _, body := range []string{`{}`, `{"email":"test@example.invalid"}`, `{"email":"bad\n@example.invalid","verified_email":true}`} {
		o := testOAuth(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
		if _, err := o.userEmail(context.Background(), fakeAccess); !errors.Is(err, errOAuth) {
			t.Fatal("invalid userinfo accepted")
		}
	}
}

func TestOAuthRedirectAndErrorRedaction(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer other.Close()
	for _, status := range []int{302, 307, 400, 500} {
		o := testOAuth(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", other.URL+"?token="+fakeAccess)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, fakeAccess+fakeRefresh+fakeCode)
		})
		_, err := o.tokens(context.Background(), url.Values{"refresh_token": {fakeRefresh}}, fakeRefresh)
		if !errors.Is(err, errOAuth) {
			t.Fatal("failed exchange not rejected")
		}
		assertNoSecrets(t, err.Error())
		_, err = o.userEmail(context.Background(), fakeAccess)
		if !errors.Is(err, errOAuth) {
			t.Fatal("failed userinfo not rejected")
		}
		assertNoSecrets(t, err.Error())
	}
	if redirected.Load() != 0 {
		t.Fatal("OAuth followed credential-bearing redirect")
	}
}

func TestPrivateCredentialAtomicWriteAndRefusals(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "own.json")
	file, err := openPrivateCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.root.Close()
	old := expiredOwnToken()
	if err := file.write(old, false, nil); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	before, _ := reader.Stat()
	fresh := old
	fresh.AccessToken = "new-test-access"
	fresh.Expiry = time.Now().Add(time.Hour)
	if !errors.Is(file.write(fresh, false, nil), errCredentialExists) {
		t.Fatal("implicit overwrite allowed")
	}
	if err := file.write(fresh, true, before); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if os.SameFile(before, after) || after.Mode().Perm() != 0600 {
		t.Fatal("write was not atomic 0600 replacement")
	}
	oldData, _ := io.ReadAll(reader)
	oldToken, _ := decodeOwnToken(oldData)
	if oldToken.AccessToken != old.AccessToken {
		t.Fatal("old inode modified")
	}
	if file.write(old, true, before) == nil {
		t.Fatal("stale refresh overwrite accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary credentials left behind")
	}

	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	linked, err := openPrivateCredentialFile(link)
	if err != nil {
		t.Fatal(err)
	}
	defer linked.root.Close()
	if _, _, err := linked.read(); err == nil {
		t.Fatal("read followed symlink")
	}
	if linked.write(old, true, nil) == nil {
		t.Fatal("force accepted symlink output")
	}
	if _, err := (&localCredentials{file: link}).Load(context.Background()); err == nil {
		t.Fatal("read-only mode followed symlink")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if file.write(old, true, nil) == nil {
		t.Fatal("insecure existing file accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateCredentialFile(path); err == nil {
		t.Fatal("public parent accepted")
	}
	_ = os.Chmod(dir, 0700)
	parentLink := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := openPrivateCredentialFile(filepath.Join(parentLink, "own.json")); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestFileRefreshRotationExpiryAndSingleflight(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserved", true: "rotated"}[rotated], func(t *testing.T) {
			var calls atomic.Int32
			o := testOAuth(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_ = r.ParseForm()
				if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != fakeRefresh {
					t.Error("refresh form incorrect")
				}
				refresh := ""
				if rotated {
					refresh = "rotated-test-refresh"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "refreshed-test-access", "refresh_token": refresh, "token_type": "Bearer", "expires_in": 3600})
			})
			path := filepath.Join(t.TempDir(), "own.json")
			writeOwnFixture(t, path, expiredOwnToken())
			s := &localCredentials{file: path, refreshFile: true, oauth: o}
			before := time.Now()
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := s.Load(context.Background())
					if err != nil || c.AccessToken != "refreshed-test-access" || c.Expiry.Before(before.Add(3599*time.Second)) || c.Expiry.After(time.Now().Add(3601*time.Second)) {
						t.Error("refresh credential or expiry incorrect")
					}
				}()
			}
			wg.Wait()
			if calls.Load() != 1 {
				t.Fatal("refresh not singleflight")
			}
			data, _ := os.ReadFile(path)
			token, err := decodeOwnToken(data)
			wantRefresh := fakeRefresh
			if rotated {
				wantRefresh = "rotated-test-refresh"
			}
			if err != nil || token.RefreshToken != wantRefresh {
				t.Fatal("refresh token rotation incorrect")
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatal("refreshed file not private")
			}
			fresh := token
			fresh.AccessToken = "external-login-test-access"
			writeOwnFixture(t, path, fresh)
			c, err := s.Load(context.Background())
			if err != nil || c.AccessToken != fresh.AccessToken || calls.Load() != 1 {
				t.Fatal("external login replacement not reread")
			}
		})
	}
}

func TestRefreshOptInOwnFormatAndThreshold(t *testing.T) {
	var calls atomic.Int32
	o := testOAuth(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"access_token":"`+fakeAccess+`","refresh_token":"`+fakeRefresh+`","token_type":"Bearer","expires_in":3600}`)
	})
	path := filepath.Join(t.TempDir(), "own.json")
	writeOwnFixture(t, path, expiredOwnToken())
	if _, err := (&localCredentials{file: path, oauth: o}).Load(context.Background()); err == nil || calls.Load() != 0 {
		t.Fatal("refresh happened without opt-in")
	}
	if _, err := (&localCredentials{refreshFile: true, oauth: o}).Load(context.Background()); err == nil || calls.Load() != 0 {
		t.Fatal("file refresh accessed keychain")
	}
	for _, data := range []string{
		`{"token":{"access_token":"private"},"auth_method":"consumer"}`,
		`{"access_token":"private","refresh_token":"private","token_type":"Bearer","expired":"2099-01-01T00:00:00Z","type":"antigravity"}`,
		`{"access_token":"private","token_type":"Bearer","expiry":"2099-01-01T00:00:00Z"}`,
		`{"access_token":"private","refresh_token":"private","token_type":"Bearer"}`,
		`{"access_token":"private","refresh_token":"private","token_type":"Bearer","expiry":"invalid"}`,
	} {
		_ = os.WriteFile(path, []byte(data), 0600)
		if _, err := (&localCredentials{file: path, refreshFile: true, oauth: o}).Load(context.Background()); err == nil || calls.Load() != 0 {
			t.Fatal("foreign or incomplete token refreshed")
		}
	}
	near := expiredOwnToken()
	near.Expiry = time.Now().Add(2 * time.Minute)
	writeOwnFixture(t, path, near)
	s := &localCredentials{file: path, refreshFile: true, oauth: o}
	if _, err := s.Load(context.Background()); err != nil || calls.Load() != 0 {
		t.Fatal("unexpired token refreshed too early")
	}
	near.Expiry = time.Now().Add(30 * time.Second)
	writeOwnFixture(t, path, near)
	if _, err := s.Load(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("near-expiry token not refreshed")
	}
}

func TestRefreshExternalLoginWins(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	o := testOAuth(t, func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, `{"access_token":"refresh-loser","token_type":"Bearer","expires_in":3600}`)
	})
	path := filepath.Join(t.TempDir(), "own.json")
	writeOwnFixture(t, path, expiredOwnToken())
	s := &localCredentials{file: path, refreshFile: true, oauth: o}
	result := make(chan credential, 1)
	go func() { c, _ := s.Load(context.Background()); result <- c }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh not started")
	}
	fresh := expiredOwnToken()
	fresh.AccessToken = "external-login-winner"
	fresh.Expiry = time.Now().Add(time.Hour)
	writeOwnFixture(t, path, fresh)
	close(release)
	select {
	case c := <-result:
		if c.AccessToken != fresh.AccessToken {
			t.Fatal("refresh overwrote external login")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not complete")
	}
	data, _ := os.ReadFile(path)
	token, _ := decodeOwnToken(data)
	if token.AccessToken != fresh.AccessToken {
		t.Fatal("external login lost on disk")
	}
}

func TestLoginCancellationTimeoutAndDenial(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "denied"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			o := testOAuth(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "timeout" {
				var timeoutCancel context.CancelFunc
				ctx, timeoutCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer timeoutCancel()
			}
			path := filepath.Join(privateTempDir(t), "own.json")
			out := newLoginOutput()
			result := make(chan error, 1)
			go func() { result <- o.login(ctx, path, 0, false, out) }()
			u := awaitLoginURL(t, out)
			if mode == "cancel" {
				cancel()
			}
			if mode == "denied" {
				sendCallback(t, u, url.Values{"state": {u.Query().Get("state")}, "error": {"access_denied"}})
			}
			if err := awaitLoginResult(t, result); !errors.Is(err, errLogin) {
				t.Fatal("cancellation/denial not rejected")
			}
			if calls.Load() != 0 {
				t.Fatal("cancelled login called OAuth API")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("cancelled login created credentials")
			}
			assertNoSecrets(t, out.text())
		})
	}
}

func TestRefreshCancellationAndFailurePreserveFile(t *testing.T) {
	for _, mode := range []string{"timeout", "failure"} {
		t.Run(mode, func(t *testing.T) {
			o := testOAuth(t, func(w http.ResponseWriter, r *http.Request) {
				if mode == "timeout" {
					_, _ = io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
					return
				}
				w.WriteHeader(400)
				_, _ = io.WriteString(w, fakeAccess+fakeRefresh)
			})
			path := filepath.Join(t.TempDir(), "own.json")
			writeOwnFixture(t, path, expiredOwnToken())
			before, _ := os.ReadFile(path)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := (&localCredentials{file: path, refreshFile: true, oauth: o}).Load(ctx)
			if !errors.Is(err, errCredentials) {
				t.Fatal("refresh failure not generic")
			}
			assertNoSecrets(t, err.Error())
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("failed refresh modified credentials")
			}
		})
	}
}

func TestLoginFlagsAndExistingRefusal(t *testing.T) {
	for _, args := range [][]string{nil, {"--credential-file", "x", "--callback-port", "0"}, {"--credential-file", "x", "--callback-port", "65536"}, {"--unknown", fakeAccess}, {"--credential-file", "x", "unexpected"}} {
		err := runLogin(args)
		if err == nil {
			t.Fatal("invalid login flags accepted")
		}
		assertNoSecrets(t, err.Error())
	}
	path := filepath.Join(t.TempDir(), "own.json")
	writeOwnFixture(t, path, expiredOwnToken())
	o := testOAuth(t, func(http.ResponseWriter, *http.Request) { t.Error("existing-file refusal accessed OAuth") })
	var out bytes.Buffer
	if err := o.login(context.Background(), path, 0, false, &out); !errors.Is(err, errCredentialExists) || out.Len() != 0 {
		t.Fatal("existing credentials not refused before starting login")
	}
}

func TestCredentialLockCancellationAndSymlink(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "own.json")
	file, err := openPrivateCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.root.Close()
	unlock, err := file.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	other, err := openPrivateCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.root.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if release, err := other.lock(ctx); err == nil {
		release()
		t.Fatal("second owner ignored lock")
	}
	unlock()
	release, err := other.lock(context.Background())
	if err != nil {
		t.Fatal("lock not released")
	}
	release()
	info, err := os.Stat(path + ".lock")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("lock file not private")
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", path+".lock"); err != nil {
		t.Fatal(err)
	}
	if release, err := file.lock(context.Background()); err == nil {
		release()
		t.Fatal("lock followed symlink")
	}
}

func TestForceLoginSerializesWithRefresh(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	userinfo := make(chan struct{})
	var once sync.Once
	o := testOAuth(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/userinfo" {
			_, _ = io.WriteString(w, `{"email":"new-login@example.invalid","verified_email":true}`)
			close(userinfo)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			close(entered)
			<-release
			_, _ = io.WriteString(w, `{"access_token":"old-account-refreshed","token_type":"Bearer","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"new-account-login","refresh_token":"new-account-refresh","token_type":"Bearer","expires_in":3600}`)
	})
	// Also release the blocked test endpoint if a test assertion fails.
	defer once.Do(func() { close(release) })
	path := filepath.Join(privateTempDir(t), "own.json")
	writeOwnFixture(t, path, expiredOwnToken())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	refreshResult := make(chan error, 1)
	go func() {
		_, err := (&localCredentials{file: path, refreshFile: true, oauth: o}).Load(ctx)
		refreshResult <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("refresh did not begin")
	}
	out := newLoginOutput()
	loginResult := make(chan error, 1)
	go func() { loginResult <- o.login(ctx, path, 0, true, out) }()
	u := awaitLoginURL(t, out)
	sendCallback(t, u, url.Values{"state": {u.Query().Get("state")}, "code": {fakeCode}})
	select {
	case <-userinfo:
	case <-ctx.Done():
		t.Fatal("login did not fetch userinfo")
	}
	select {
	case <-loginResult:
		t.Fatal("login did not wait for refresh owner")
	default:
	}
	once.Do(func() { close(release) })
	if err := awaitLoginResult(t, refreshResult); err != nil {
		t.Fatal(err)
	}
	if err := awaitLoginResult(t, loginResult); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	token, err := decodeOwnToken(data)
	if err != nil || token.AccessToken != "new-account-login" || token.RefreshToken != "new-account-refresh" {
		t.Fatal("old refresh overwrote new account")
	}
	assertNoSecrets(t, out.text())
}
