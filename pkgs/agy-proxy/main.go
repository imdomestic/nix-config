package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func run() error {
	listen := flag.String("listen", "127.0.0.1:8319", "loopback listen address")
	openaiCompat := flag.Bool("openai-compat", false, "enable stateless OpenAI-compatible Chat, Responses, image and file-audio endpoints")
	keyFile := flag.String("client-key-file", "", "private file containing the proxy client Bearer key")
	credentialFile := flag.String("credential-file", "", "private OAuth JSON file; never in the Nix store")
	refreshFile := flag.Bool("refresh-credentials", false, "refresh and atomically persist this service's own OAuth credential file")
	oauthFile := flag.String("oauth-client-file", "", "private runtime OAuth client configuration, required for independent refresh")
	keychain := flag.Bool("keychain", false, "enable Gemini API using the native macOS gemini/antigravity keychain")
	refreshAgy := flag.String("refresh-with-agy", "", "optional absolute agy path; refresh expired keychain credentials with agy models")
	ua := flag.String("user-agent", defaultUserAgent, "Gemini upstream UA; default is the observed CLI 1.5.9 profile")
	maxBody := flag.Int64("max-body-bytes", 64<<20, "maximum request and non-streaming response bytes")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !(host == "localhost" || net.ParseIP(host).IsLoopback()) {
		return errors.New("listen must be a loopback address; use an authenticated TLS frontend for remote access")
	}
	if *maxBody <= 0 || *maxBody > 1<<30 {
		return errors.New("max-body-bytes must be between 1 and 1073741824")
	}
	if *ua == "" || strings.ContainsAny(*ua, "\r\n") {
		return errors.New("invalid user-agent")
	}
	if *keychain && (*credentialFile != "" || runtime.GOOS != "darwin") {
		return errors.New("keychain requires macOS and cannot be combined with credential-file")
	}
	if *refreshAgy != "" && (!*keychain || !strings.HasPrefix(*refreshAgy, "/")) {
		return errors.New("refresh-with-agy requires keychain and an absolute executable path")
	}
	if *refreshFile && *credentialFile == "" {
		return errors.New("refresh-credentials requires this service's own credential-file")
	}
	var key string
	if *keyFile != "" {
		data, err := readRuntimeSecret(*keyFile, 4096)
		if err != nil {
			return errors.New("client-key-file must be a private file or protected systemd credential, at most 4096 bytes")
		}
		key = strings.TrimSpace(string(data))
		if len(key) < 16 || strings.ContainsAny(key, " \r\n\t") {
			return errors.New("client key must have at least 16 characters and contain no whitespace")
		}
	}
	var oauth *oauthClient
	if *refreshFile {
		if *oauthFile == "" {
			return errors.New("refresh-credentials requires oauth-client-file")
		}
		oauth, err = loadOAuthClient(*oauthFile)
		if err != nil {
			return err
		}
	}
	var source credentialSource
	if *keychain || *credentialFile != "" {
		if key == "" {
			return errors.New("Gemini API requires client-key-file; never expose a subscription through an anonymous local endpoint")
		}
		source = &localCredentials{file: *credentialFile, account: "antigravity", refreshAgy: *refreshAgy, refreshFile: *refreshFile, oauth: oauth}
	}
	origin, _ := url.Parse("https://daily-cloudcode-pa.googleapis.com")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 45 * time.Second
	transport.MaxIdleConnsPerHost = 8
	if *openaiCompat && source == nil {
		return errors.New("openai-compat requires keychain or credential-file and a proxy client key")
	}
	p := newProxy(origin, transport, source, key, *ua, *maxBody)
	p.openaiCompat = *openaiCompat
	server := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return errors.New("cannot bind listen address")
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	mode := "native passthrough"
	if source != nil {
		mode += " + authenticated Gemini API"
	}
	log.Printf("agy-proxy listening on %s (%s); no request/token logging", listener.Addr(), mode)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("HTTP server failed")
	}
	return nil
}

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "login" {
		err = runLogin(os.Args[2:])
	} else {
		err = run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agy-proxy:", err)
		os.Exit(1)
	}
}
