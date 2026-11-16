package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Public installed-app scopes; client credentials come only from a private runtime file.
const oauthScopes = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/aicode https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs"

var (
	errOAuth            = errors.New("OAuth request failed; no credentials saved")
	errLogin            = errors.New("OAuth login cancelled, timed out, or denied; no credentials saved")
	errCredentialFile   = errors.New("credential-file must be owned by this user, private, and non-symlink, in a private directory")
	errCredentialExists = errors.New("credential-file already exists; use --force to explicitly replace your own credentials")
)

// Endpoints and HTTP transport are injectable only in Go tests, never via CLI.
type oauthClient struct {
	client                                        *http.Client
	authEndpoint, tokenEndpoint, userInfoEndpoint string
	clientID, clientSecret                        string
}

type oauthClientMetadata struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func loadOAuthClient(path string) (*oauthClient, error) {
	data, err := readRuntimeSecret(path, 1<<20)
	var metadata oauthClientMetadata
	if err != nil || json.Unmarshal(data, &metadata) != nil || !validOAuthToken(metadata.ClientID) || !validOAuthToken(metadata.ClientSecret) {
		return nil, errors.New("invalid OAuth client configuration")
	}
	return newOAuthClient(metadata), nil
}

func newOAuthClient(metadata oauthClientMetadata) *oauthClient {
	return &oauthClient{
		clientID: metadata.ClientID, clientSecret: metadata.ClientSecret,
		client:           &http.Client{Timeout: 45 * time.Second},
		authEndpoint:     "https://accounts.google.com/o/oauth2/v2/auth",
		tokenEndpoint:    "https://oauth2.googleapis.com/token",
		userInfoEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo?alt=json",
	}
}

func randomOAuthValue() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errOAuth
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (o *oauthClient) authURL(state, verifier, redirect string) string {
	q := url.Values{
		"client_id": {o.clientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {oauthScopes}, "access_type": {"offline"}, "prompt": {"select_account consent"},
		"state": {state}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	return o.authEndpoint + "?" + q.Encode()
}

func validOAuthToken(s string) bool {
	if s == "" || len(s) > 16<<10 {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

type ownToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
}

func decodeOwnToken(data []byte) (ownToken, error) {
	var token ownToken
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields() // Native wrappers and CLIProxy auth-directory records are not ours.
	if d.Decode(&token) != nil || d.Decode(new(any)) != io.EOF || !validOAuthToken(token.AccessToken) || !validOAuthToken(token.RefreshToken) || !strings.EqualFold(token.TokenType, "Bearer") || token.Expiry.IsZero() {
		return ownToken{}, errCredentials
	}
	return token, nil
}

func (o *oauthClient) request(ctx context.Context, method, endpoint string, form url.Values, access string, result any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errOAuth
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if access != "" {
		r.Header.Set("Authorization", "Bearer "+access)
	}
	client := *o.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(r)
	if err != nil {
		return errOAuth
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errOAuth
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, result) != nil {
		return errOAuth
	}
	return nil
}

func (o *oauthClient) tokens(ctx context.Context, form url.Values, previousRefresh string) (ownToken, error) {
	form.Set("client_id", o.clientID)
	form.Set("client_secret", o.clientSecret)
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if o.request(ctx, "POST", o.tokenEndpoint, form, "", &response) != nil {
		return ownToken{}, errOAuth
	}
	if response.RefreshToken == "" {
		response.RefreshToken = previousRefresh
	}
	if !validOAuthToken(response.AccessToken) || !validOAuthToken(response.RefreshToken) || !strings.EqualFold(response.TokenType, "Bearer") || response.ExpiresIn <= 60 || response.ExpiresIn > 86400 {
		return ownToken{}, errOAuth
	}
	return ownToken{response.AccessToken, response.RefreshToken, "Bearer", time.Now().UTC().Add(time.Duration(response.ExpiresIn) * time.Second)}, nil
}

func (o *oauthClient) refresh(ctx context.Context, refreshToken string) (ownToken, error) {
	return o.tokens(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, refreshToken)
}

func (o *oauthClient) userEmail(ctx context.Context, token string) (string, error) {
	var info struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified_email"`
	}
	if o.request(ctx, "GET", o.userInfoEndpoint, nil, token, &info) != nil || !info.Verified || !strings.Contains(info.Email, "@") || !validOAuthToken(info.Email) || len(info.Email) > 320 {
		return "", errOAuth
	}
	return info.Email, nil
}

// OpenRoot anchors all output operations to the directory even if its path moves.
type privateCredentialFile struct {
	root *os.Root
	name string
}

func privateOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}

func openPrivateCredentialFile(path string) (*privateCredentialFile, error) {
	return openCredentialFile(path, true)
}

func openCredentialFile(path string, privateParent bool) (*privateCredentialFile, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, errCredentialFile
	}
	parent := filepath.Dir(absolute)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || (privateParent && !privateOwned(info)) {
		return nil, errCredentialFile
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, errCredentialFile
	}
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) || (privateParent && !privateOwned(opened)) {
		root.Close()
		return nil, errCredentialFile
	}
	return &privateCredentialFile{root, filepath.Base(absolute)}, nil
}

// Never remove this sidecar: unlinking a flock inode would permit two owners.
func (f *privateCredentialFile) lock(ctx context.Context) (func(), error) {
	parent, err := f.root.Stat(".")
	if err != nil || !parent.IsDir() || !privateOwned(parent) {
		return nil, errCredentialFile
	}
	name := f.name + ".lock"
	var file *os.File
	for attempts := 0; attempts < 3; attempts++ {
		info, statErr := f.root.Lstat(name)
		flags := os.O_RDWR | syscall.O_NOFOLLOW
		if os.IsNotExist(statErr) {
			flags |= os.O_CREATE | os.O_EXCL
		} else if statErr != nil || !info.Mode().IsRegular() || !privateOwned(info) {
			return nil, errCredentialFile
		}
		file, err = f.root.OpenFile(name, flags, 0600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return nil, errCredentialFile
		}
		opened, openErr := file.Stat()
		current, currentErr := f.root.Lstat(name)
		if openErr != nil || currentErr != nil || !current.Mode().IsRegular() || !privateOwned(opened) || !os.SameFile(opened, current) || (info != nil && !os.SameFile(info, opened)) {
			file.Close()
			return nil, errCredentialFile
		}
		break
	}
	if file == nil {
		return nil, errCredentialFile
	}
	for {
		if ctx.Err() != nil {
			file.Close()
			return nil, errCredentialFile
		}
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			file.Close()
			return nil, errCredentialFile
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			file.Close()
			return nil, errCredentialFile
		case <-timer.C:
		}
	}
}

func (f *privateCredentialFile) existing() (os.FileInfo, error) {
	info, err := f.root.Lstat(f.name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || !privateOwned(info) || info.Size() > 1<<20 {
		return nil, errCredentialFile
	}
	return info, nil
}

func (f *privateCredentialFile) read() ([]byte, os.FileInfo, error) {
	info, err := f.existing()
	if err != nil || info == nil {
		return nil, nil, errCredentialFile
	}
	file, err := f.root.OpenFile(f.name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, errCredentialFile
	}
	defer file.Close()
	opened, err := file.Stat()
	current, currentErr := f.existing()
	if err != nil || currentErr != nil || !sameCredentialFile(info, current) || !os.SameFile(info, opened) || !privateOwned(opened) {
		return nil, nil, errCredentialFile
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, nil, errCredentialFile
	}
	finished, err := file.Stat()
	if err != nil || !sameCredentialFile(opened, finished) || !privateOwned(finished) {
		return nil, nil, errCredentialFile
	}
	return data, opened, nil
}

func sameCredentialFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}

// expected prevents an in-flight refresh overwriting a completed external login.
func (f *privateCredentialFile) write(token ownToken, force bool, expected os.FileInfo) error {
	parent, err := f.root.Stat(".")
	if err != nil || !parent.IsDir() || !privateOwned(parent) {
		return errCredentialFile
	}
	info, err := f.existing()
	if err != nil {
		return err
	}
	if expected != nil && !sameCredentialFile(info, expected) {
		return errCredentials
	}
	if info != nil && !force {
		return errCredentialExists
	}
	data, err := json.Marshal(token)
	if err != nil {
		return errCredentialFile
	}
	suffix, err := randomOAuthValue()
	if err != nil {
		return errCredentialFile
	}
	tmp := ".agy-oauth-" + suffix
	file, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errCredentialFile
	}
	defer f.root.Remove(tmp)
	if _, err = file.Write(append(data, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errCredentialFile
	}
	info, err = f.existing()
	if err != nil {
		return err
	}
	if expected != nil && !sameCredentialFile(info, expected) {
		return errCredentials
	}
	if force {
		err = f.root.Rename(tmp, f.name)
	} else {
		// Link is atomic create-if-absent, unlike a stat followed by Rename.
		err = f.root.Link(tmp, f.name)
	}
	if err != nil {
		if !force && os.IsExist(err) {
			return errCredentialExists
		}
		return errCredentialFile
	}
	return nil
}

func runLogin(args []string) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("credential-file", "", "private output JSON file (required)")
	clientFile := flags.String("oauth-client-file", "", "private runtime OAuth client configuration (required)")
	port := flags.Int("callback-port", 51121, "SSH-forwarded loopback OAuth callback port")
	force := flags.Bool("force", false, "explicitly replace your own existing credential file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || *clientFile == "" || *port < 1 || *port > 65535 {
		return errors.New("login requires --credential-file PATH and --oauth-client-file PATH; optional --callback-port 1..65535 and --force")
	}
	oauth, err := loadOAuthClient(*clientFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return oauth.login(ctx, *path, *port, *force, os.Stdout)
}

func (o *oauthClient) login(ctx context.Context, path string, port int, force bool, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if ctx.Err() != nil {
		return errLogin
	}
	file, err := openPrivateCredentialFile(path)
	if err != nil {
		return err
	}
	defer file.root.Close()
	info, err := file.existing()
	if err != nil {
		return err
	}
	if info != nil && !force {
		return errCredentialExists
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return errors.New("cannot bind OAuth loopback callback port")
	}
	defer listener.Close()
	port = listener.Addr().(*net.TCPAddr).Port
	redirect := fmt.Sprintf("http://localhost:%d/oauth-callback", port)
	state, err := randomOAuthValue()
	if err != nil {
		return err
	}
	verifier, err := randomOAuthValue()
	if err != nil {
		return err
	}
	type callback struct {
		code   string
		denied bool
	}
	result := make(chan callback, 1)
	var once sync.Once
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			q, parseErr := url.ParseQuery(r.URL.RawQuery)
			if r.Method != "GET" || r.URL.Path != "/oauth-callback" || parseErr != nil || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
				http.Error(w, "Invalid OAuth callback", 400)
				return
			}
			denied := len(q["error"]) == 1 && q.Get("error") != "" && len(q["code"]) == 0
			if !denied && (len(q["error"]) != 0 || len(q["code"]) != 1 || !validOAuthToken(q.Get("code"))) {
				http.Error(w, "Invalid OAuth callback", 400)
				return
			}
			once.Do(func() { result <- callback{q.Get("code"), denied} })
			_, _ = io.WriteString(w, "Authorization received. Return to the SSH terminal.\n")
		}),
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer server.Close()
	if _, err := fmt.Fprintf(out, "Forward port with ssh -L %d:127.0.0.1:%d <host>, then open this URL in your own browser and select your own account (10 minute limit):\n%s\n", port, port, o.authURL(state, verifier, redirect)); err != nil {
		return errLogin
	}
	var received callback
	select {
	case <-ctx.Done():
		return errLogin
	case <-served:
		return errLogin
	case received = <-result:
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	_ = server.Shutdown(shutdownCtx)
	shutdownCancel()
	if received.denied || ctx.Err() != nil {
		return errLogin
	}
	token, err := o.tokens(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {received.code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}, "")
	if err != nil {
		return errOAuth
	}
	email, err := o.userEmail(ctx, token.AccessToken)
	if err != nil {
		return errOAuth
	}
	if ctx.Err() != nil {
		return errLogin
	}
	writeCtx, writeCancel := context.WithTimeout(ctx, 45*time.Second)
	defer writeCancel()
	unlock, err := file.lock(writeCtx)
	if err != nil {
		return errCredentialFile
	}
	defer unlock()
	if err := file.write(token, force, nil); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Signed in as %s; private credentials saved. No onboarding or subscription changes performed.\n", email)
	if err != nil {
		return errors.New("credentials saved, but cannot write login confirmation")
	}
	return nil
}
