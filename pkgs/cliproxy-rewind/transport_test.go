package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var modelTestIPs = []netip.Addr{
	netip.MustParseAddr("2001:db8::1"),
	netip.MustParseAddr("192.0.2.1"),
}

func modelTestCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func modelTestConnector(roots *x509.CertPool) *modelTLSConnector {
	return &modelTLSConnector{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return modelTestIPs, nil
		},
		tlsConfig: &tls.Config{RootCAs: roots},
		timeout:   time.Second * 5,
	}
}

// Every blocking test operation has a watchdog, never a scheduling sleep.
func modelTestAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for transport test synchronization")
		var zero T
		return zero
	}
}

type modelTestTrackedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *modelTestTrackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type modelTestPeerResult struct {
	data  []byte
	state tls.ConnectionState
	err   error
}

func modelTestTLSPeer(t *testing.T, cert tls.Certificate) (*modelTestTrackedConn, <-chan modelTestPeerResult) {
	t.Helper()
	// Real loopback TCP buffers simultaneous TLS flights/alerts; net.Pipe can
	// deadlock on a certificate alert while the server writes its Finished.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	tracked := &modelTestTrackedConn{Conn: client, closed: make(chan struct{})}
	result := make(chan modelTestPeerResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
		err := conn.Handshake()
		var data []byte
		if err == nil {
			data, err = io.ReadAll(conn)
		}
		result <- modelTestPeerResult{data: data, state: conn.ConnectionState(), err: err}
	}()
	t.Cleanup(func() {
		tracked.Close()
		server.Close()
		modelTestAwait(t, done)
	})
	return tracked, result
}

// Reads the ClientHello but never responds: TCP success must not win the race.
func modelTestStalledPeer(t *testing.T) (*modelTestTrackedConn, <-chan struct{}, <-chan []byte) {
	t.Helper()
	client, server := net.Pipe()
	tracked := &modelTestTrackedConn{Conn: client, closed: make(chan struct{})}
	hello := make(chan struct{})
	result := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		var data bytes.Buffer
		header := make([]byte, 5)
		if _, err := io.ReadFull(server, header); err == nil {
			data.Write(header)
			payload := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
			if _, err := io.ReadFull(server, payload); err == nil {
				data.Write(payload)
				close(hello)
			}
		}
		_, _ = io.Copy(&data, server)
		result <- data.Bytes()
	}()
	t.Cleanup(func() {
		tracked.Close()
		server.Close()
		modelTestAwait(t, done)
	})
	return tracked, hello, result
}

func modelTestAssertOnlyHello(t *testing.T, data []byte) {
	t.Helper()
	if len(data) < 5 || data[0] != 22 || int(binary.BigEndian.Uint16(data[3:5])) != len(data)-5 {
		t.Fatalf("stalled loser received more than a single TLS ClientHello record (%d bytes)", len(data))
	}
}

func modelTestHTTPServer(t *testing.T, cert tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	server.EnableHTTP2 = true // The client must still negotiate HTTP/1.1.
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func modelTestInstallConnector(client *http.Client, connector *modelTLSConnector) {
	client.Transport.(*modelHTTPTransport).DialTLSContext = connector.dialTLSContext
}

func TestModelTransportConfiguration(t *testing.T) {
	client := newModelHTTPClient()
	defer client.CloseIdleConnections()
	transport := client.Transport.(*modelHTTPTransport).Transport
	if transport.Proxy != nil || !transport.DisableCompression || transport.ForceAttemptHTTP2 || transport.TLSNextProto == nil || len(transport.TLSNextProto) != 0 {
		t.Fatal("transport permits proxies, automatic compression or HTTP/2")
	}
	if transport.MaxConnsPerHost != 16 || transport.MaxIdleConnsPerHost != 16 || transport.MaxIdleConns < 16 || transport.IdleConnTimeout <= 0 || transport.DialTLSContext == nil || modelConnectTimeout != 10*time.Second {
		t.Fatal("incorrect connection budget or pooling configuration")
	}
	if client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects are followed")
	}
	for _, scheme := range []string{"http", "ftp", "file", "wss"} {
		req, err := http.NewRequest(http.MethodGet, scheme+"://model.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
			t.Fatalf("accepted scheme %s: %v", scheme, err)
		}
	}
}

func TestModelTLSConcurrentFamiliesStalledHandshake(t *testing.T) {
	cert, roots := modelTestCertificate(t, "model.test")
	var requests atomic.Int32
	server := modelTestHTTPServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 1 || r.TLS.ServerName != "model.test" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("incorrect HTTP version, SNI or compression")
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	loser, hello, loserData := modelTestStalledPeer(t)
	connector := modelTestConnector(roots)
	started := make(chan string, 2)
	release := make(chan struct{})
	dialer := &net.Dialer{}
	connector.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		started <- network
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if network == "tcp6" {
			return loser, nil
		}
		select {
		case <-hello:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return dialer.DialContext(ctx, "tcp4", server.Listener.Addr().String())
	}
	client := newModelHTTPClient()
	modelTestInstallConnector(client, connector)
	defer client.CloseIdleConnections()
	type response struct {
		data []byte
		err  error
	}
	finished := make(chan response, 1)
	go func() {
		r, err := client.Post("https://model.test/request", "application/json", strings.NewReader("private model payload"))
		if err != nil {
			finished <- response{err: err}
			return
		}
		defer r.Body.Close()
		data, err := io.ReadAll(r.Body)
		finished <- response{data, err}
	}()
	first, second := modelTestAwait(t, started), modelTestAwait(t, started)
	if first == second || (first != "tcp4" && first != "tcp6") || (second != "tcp4" && second != "tcp6") {
		t.Fatalf("both families did not start concurrently: %q, %q", first, second)
	}
	close(release)
	r := modelTestAwait(t, finished)
	if r.err != nil || string(r.data) != "private model payload" || requests.Load() != 1 {
		t.Fatalf("valid other family did not win: %+v", r)
	}
	modelTestAwait(t, loser.closed)
	modelTestAssertOnlyHello(t, modelTestAwait(t, loserData))
}

func TestModelTLSConcurrentValidatedWinners(t *testing.T) {
	v6Cert, roots := modelTestCertificate(t, "model.test")
	v4Cert, _ := modelTestCertificate(t, "model.test")
	roots.AddCert(modelTestParsedCertificate(t, v4Cert))
	v6, v6Result := modelTestTLSPeer(t, v6Cert)
	v4, v4Result := modelTestTLSPeer(t, v4Cert)
	connector := modelTestConnector(roots)
	validated := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	connector.tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 {
			return errors.New("callback ran before certificate validation")
		}
		validated <- struct{}{}
		<-release
		return nil
	}
	connector.dial = func(_ context.Context, network, _ string) (net.Conn, error) {
		if network == "tcp6" {
			return v6, nil
		}
		return v4, nil
	}
	type outcome struct {
		conn net.Conn
		err  error
	}
	finished := make(chan outcome, 1)
	go func() {
		conn, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443")
		finished <- outcome{conn, err}
	}()
	modelTestAwait(t, validated)
	modelTestAwait(t, validated)
	releaseOnce.Do(func() { close(release) })
	result := modelTestAwait(t, finished)
	if result.err != nil {
		t.Fatal(result.err)
	}
	winner := result.conn.(*tls.Conn).NetConn()
	loser := v4
	winnerResult, loserResult := v6Result, v4Result
	if winner == v4 {
		loser = v6
		winnerResult, loserResult = v4Result, v6Result
	} else if winner != v6 {
		t.Fatal("unknown race winner")
	}
	// Losing workers are already joined, including a simultaneously successful
	// TLS handshake. Only the returned connection can receive a request.
	modelTestAwait(t, loser.closed)
	payload := "POST /model HTTP/1.1\r\nHost: model.test\r\n\r\nprivate payload"
	if _, err := io.WriteString(result.conn, payload); err != nil {
		t.Fatal(err)
	}
	result.conn.Close()
	if data := modelTestAwait(t, winnerResult).data; string(data) != payload {
		t.Fatalf("winning connection did not receive the request: %q", data)
	}
	if data := modelTestAwait(t, loserResult).data; len(data) != 0 {
		t.Fatalf("validated loser received HTTP request bytes: %q", data)
	}
}

func TestModelTLSFallbackWithinFamily(t *testing.T) {
	for _, failure := range []string{"tcp", "tls"} {
		t.Run(failure, func(t *testing.T) {
			cert, roots := modelTestCertificate(t, "model.test")
			wrongCert, _ := modelTestCertificate(t, "wrong.test")
			roots.AddCert(modelTestParsedCertificate(t, wrongCert))
			bad, badResult := modelTestTLSPeer(t, wrongCert)
			good, goodResult := modelTestTLSPeer(t, cert)
			connector := modelTestConnector(roots)
			connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{modelTestIPs[0], modelTestIPs[0], netip.MustParseAddr("2001:db8::2"), modelTestIPs[1]}, nil
			}
			var mu sync.Mutex
			var attempts []string
			connector.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				mu.Lock()
				attempts = append(attempts, network+" "+address)
				mu.Unlock()
				switch address {
				case "[2001:db8::1]:443":
					if failure == "tls" {
						return bad, nil
					}
					return nil, errors.New("first TCP failed")
				case "[2001:db8::2]:443":
					return good, nil
				default:
					return nil, errors.New("IPv4 failed")
				}
			}
			conn, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443")
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if r := modelTestAwait(t, goodResult); len(r.data) != 0 || r.state.ServerName != "model.test" || r.state.NegotiatedProtocol != "http/1.1" {
				t.Fatalf("bad winning TLS state or premature HTTP bytes: %+v", r)
			}
			if failure == "tls" {
				r := modelTestAwait(t, badResult)
				if r.err == nil || len(r.data) != 0 {
					t.Fatalf("wrong certificate won or received HTTP bytes: %+v", r)
				}
				modelTestAwait(t, bad.closed)
			}
			mu.Lock()
			defer mu.Unlock()
			var v6 []string
			for _, attempt := range attempts {
				if strings.HasPrefix(attempt, "tcp6 ") {
					v6 = append(v6, attempt)
				}
			}
			if !reflect.DeepEqual(v6, []string{"tcp6 [2001:db8::1]:443", "tcp6 [2001:db8::2]:443"}) {
				t.Fatalf("family fallback order or deduplication: %v", attempts)
			}
		})
	}
}

func modelTestParsedCertificate(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestModelTLSAllFailures(t *testing.T) {
	connector := modelTestConnector(nil)
	failure := errors.New("unreachable")
	var attempts atomic.Int32
	connector.dial = func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, failure
	}
	conn, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443")
	if conn != nil || !errors.Is(err, failure) || attempts.Load() != 2 || !strings.Contains(err.Error(), "2001:db8::1") || !strings.Contains(err.Error(), "192.0.2.1") {
		t.Fatalf("missing aggregate failures: conn=%v err=%v attempts=%d", conn, err, attempts.Load())
	}
	for _, addresses := range [][]netip.Addr{nil, {{}}} {
		connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }
		if _, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443"); err == nil {
			t.Fatal("empty/invalid resolution succeeded")
		}
	}
	connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, failure }
	if _, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443"); !errors.Is(err, failure) {
		t.Fatalf("DNS failure lost: %v", err)
	}
}

func TestModelTLSCancellation(t *testing.T) {
	for _, stage := range []string{"dns", "tcp", "tls"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			connector := modelTestConnector(nil)
			entered := make(chan struct{}, 2)
			var ready <-chan struct{} = entered
			var late []*modelTestTrackedConn
			var data <-chan []byte
			if stage == "dns" {
				connector.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					entered <- struct{}{}
					<-ctx.Done()
					return nil, ctx.Err()
				}
			} else if stage == "tcp" {
				byNetwork := make(map[string]*modelTestTrackedConn)
				for _, network := range []string{"tcp4", "tcp6"} {
					client, peer := net.Pipe()
					tracked := &modelTestTrackedConn{Conn: client, closed: make(chan struct{})}
					byNetwork[network] = tracked
					late = append(late, tracked)
					t.Cleanup(func() { tracked.Close(); peer.Close() })
				}
				connector.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
					entered <- struct{}{}
					<-ctx.Done()
					// Simulate a successful TCP completion racing with cancellation.
					return byNetwork[network], nil
				}
			} else {
				peer, hello, received := modelTestStalledPeer(t)
				late = append(late, peer)
				data = received
				connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return modelTestIPs[:1], nil }
				connector.dial = func(context.Context, string, string) (net.Conn, error) { return peer, nil }
				ready = hello
			}
			finished := make(chan error, 1)
			go func() {
				_, err := connector.dialTLSContext(ctx, "tcp", "model.test:443")
				finished <- err
			}()
			modelTestAwait(t, ready)
			if stage == "tcp" {
				modelTestAwait(t, entered)
			}
			cancel()
			if err := modelTestAwait(t, finished); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			for _, conn := range late {
				modelTestAwait(t, conn.closed)
			}
			if data != nil {
				modelTestAssertOnlyHello(t, modelTestAwait(t, data))
			}
		})
	}
}

func TestModelTLSDeadline(t *testing.T) {
	for _, stage := range []string{"dns", "tcp", "tls"} {
		t.Run(stage, func(t *testing.T) {
			connector := modelTestConnector(nil)
			connector.timeout = 50 * time.Millisecond
			var loser *modelTestTrackedConn
			var data <-chan []byte
			switch stage {
			case "dns":
				connector.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			case "tcp":
				connector.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			case "tls":
				loser, _, data = modelTestStalledPeer(t)
				connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return modelTestIPs[:1], nil }
				connector.dial = func(context.Context, string, string) (net.Conn, error) { return loser, nil }
			}
			if _, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s deadline lost: %v", stage, err)
			}
			if loser != nil {
				modelTestAwait(t, loser.closed)
				modelTestAssertOnlyHello(t, modelTestAwait(t, data))
			}
		})
	}
}

func TestModelTLSCombinedDeadline(t *testing.T) {
	connector := modelTestConnector(nil)
	connector.timeout = 100 * time.Millisecond
	var dnsDeadline time.Time
	connector.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		var ok bool
		dnsDeadline, ok = ctx.Deadline()
		if !ok {
			return nil, errors.New("DNS has no deadline")
		}
		return modelTestIPs[:1], nil
	}
	peer, _, received := modelTestStalledPeer(t)
	connector.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(dnsDeadline) {
			return nil, errors.New("deadline reset between DNS and TCP")
		}
		return peer, nil
	}
	if _, err := connector.dialTLSContext(context.Background(), "tcp", "model.test:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS/TCP budget did not include TLS: %v", err)
	}
	modelTestAwait(t, peer.closed)
	modelTestAssertOnlyHello(t, modelTestAwait(t, received))
}

func TestModelTLSLiteralAddresses(t *testing.T) {
	cert, roots := modelTestCertificate(t, "model.test")
	for _, test := range []struct {
		target, network, serverName string
	}{
		{"127.0.0.1:443", "tcp4", "127.0.0.1"},
		{"[::1]:443", "tcp6", "::1"},
		{"[::ffff:127.0.0.1]:443", "tcp4", "127.0.0.1"},
		{"[::1%testzone]:443", "tcp6", "::1"},
	} {
		t.Run(test.target, func(t *testing.T) {
			connector := modelTestConnector(roots)
			connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, errors.New("literal incorrectly resolved")
			}
			peer, result := modelTestTLSPeer(t, cert)
			connector.dial = func(_ context.Context, network, address string) (net.Conn, error) {
				if network != test.network {
					return nil, fmt.Errorf("literal network %q, want %q", network, test.network)
				}
				return peer, nil
			}
			conn, err := connector.dialTLSContext(context.Background(), "tcp", test.target)
			if err != nil {
				t.Fatal(err)
			}
			state := conn.(*tls.Conn).ConnectionState()
			if state.ServerName != "" || len(state.VerifiedChains) == 0 || state.PeerCertificates[0].VerifyHostname(test.serverName) != nil {
				t.Fatalf("literal certificate was not verified: %+v", state)
			}
			conn.Close()
			if r := modelTestAwait(t, result); r.state.ServerName != "" || len(r.data) != 0 {
				t.Fatalf("IP literal emitted SNI or premature HTTP bytes: %+v", r)
			}
		})
	}
}

func TestModelTLSValidationAndSNI(t *testing.T) {
	cert, roots := modelTestCertificate(t, "model.test")
	for _, test := range []struct {
		name, target string
		roots        *x509.CertPool
		wantSuccess  bool
	}{
		{"validated", "model.test:443", roots, true},
		{"wrong-host", "wrong.test:443", roots, false},
		{"untrusted", "model.test:443", x509.NewCertPool(), false},
		{"default-roots", "model.test:443", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			connector := modelTestConnector(test.roots)
			connector.tlsConfig.ServerName = "model.test" // Must not override the target.
			connector.tlsConfig.NextProtos = []string{"h2"}
			if test.name == "default-roots" {
				connector.tlsConfig = nil
			}
			connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return modelTestIPs[1:], nil }
			peer, result := modelTestTLSPeer(t, cert)
			connector.dial = func(context.Context, string, string) (net.Conn, error) { return peer, nil }
			conn, err := connector.dialTLSContext(context.Background(), "tcp", test.target)
			if test.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				state := conn.(*tls.Conn).ConnectionState()
				if len(state.VerifiedChains) == 0 || state.ServerName != "model.test" || state.NegotiatedProtocol != "http/1.1" {
					t.Fatalf("unverified winning connection: %+v", state)
				}
				conn.Close()
			} else {
				if conn != nil || err == nil {
					t.Fatalf("invalid certificate accepted: conn=%v err=%v", conn, err)
				}
				var hostnameError x509.HostnameError
				var authorityError x509.UnknownAuthorityError
				if test.name == "wrong-host" && !errors.As(err, &hostnameError) {
					t.Fatalf("wrong-host failure was not certificate verification: %v", err)
				}
				if test.name != "wrong-host" && !errors.As(err, &authorityError) {
					t.Fatalf("untrusted failure was not certificate verification: %v", err)
				}
			}
			if r := modelTestAwait(t, result); len(r.data) != 0 {
				t.Fatalf("connection received HTTP before selection: %q", r.data)
			}
		})
	}
}

func TestModelTransportPoolingAndRedirects(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	cert, roots := modelTestCertificate(t, "model.test")
	var connections, forbidden atomic.Int32
	server := modelTestHTTPServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.TLS.NegotiatedProtocol != "http/1.1" || r.TLS.ServerName != "model.test" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("wrong wire settings")
		}
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "https://model.test/forbidden")
			w.WriteHeader(http.StatusTemporaryRedirect)
			_, _ = w.Write([]byte("redirect body"))
		case "/forbidden":
			forbidden.Add(1)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	connector := modelTestConnector(roots)
	connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return modelTestIPs[1:], nil }
	dialer := &net.Dialer{}
	connector.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		connections.Add(1)
		return dialer.DialContext(ctx, "tcp4", server.Listener.Addr().String())
	}
	client := newModelHTTPClient()
	modelTestInstallConnector(client, connector)
	defer client.CloseIdleConnections()
	for _, path := range []string{"/normal", "/normal", "/redirect"} {
		r, err := client.Get("https://model.test" + path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if path == "/redirect" && (r.StatusCode != 307 || string(data) != "redirect body") {
			t.Fatalf("redirect response was not preserved: %d %q", r.StatusCode, data)
		}
	}
	if connections.Load() != 1 || forbidden.Load() != 0 {
		t.Fatalf("pooling or redirect policy failed: connections=%d redirected=%d", connections.Load(), forbidden.Load())
	}
}

func TestModelTransportRequestCancellationDuringDial(t *testing.T) {
	for _, stage := range []string{"dns", "tls"} {
		t.Run(stage, func(t *testing.T) {
			connector := modelTestConnector(nil)
			var ready, exited <-chan struct{}
			var loserData <-chan []byte
			if stage == "dns" {
				entered, done := make(chan struct{}), make(chan struct{})
				ready, exited = entered, done
				connector.lookup = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					close(entered)
					<-ctx.Done()
					close(done)
					return nil, ctx.Err()
				}
			} else {
				peer, hello, data := modelTestStalledPeer(t)
				ready, exited, loserData = hello, peer.closed, data
				connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return modelTestIPs[:1], nil }
				connector.dial = func(context.Context, string, string) (net.Conn, error) { return peer, nil }
			}
			client := newModelHTTPClient()
			modelTestInstallConnector(client, connector)
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://model.test/", strings.NewReader("private"))
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { _, err := client.Do(req); finished <- err }()
			modelTestAwait(t, ready)
			cancel()
			if err := modelTestAwait(t, finished); !errors.Is(err, context.Canceled) {
				t.Fatalf("request did not cancel: %v", err)
			}
			modelTestAwait(t, exited) // Standard Transport alone leaves its dial running.
			if loserData != nil {
				modelTestAssertOnlyHello(t, modelTestAwait(t, loserData))
			}
		})
	}
}

func TestModelTLSInvalidTargetsAndAlreadyCanceled(t *testing.T) {
	connector := modelTestConnector(nil)
	connector.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("unexpected resolver call")
		return nil, nil
	}
	for _, target := range []string{"model.test", ":443", "model.test:", "[bad-ip"} {
		if _, err := connector.dialTLSContext(context.Background(), "tcp", target); err == nil {
			t.Fatalf("invalid target %q accepted", target)
		}
	}
	if _, err := connector.dialTLSContext(context.Background(), "udp", "model.test:443"); err == nil {
		t.Fatal("non-TCP network accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connector.dialTLSContext(ctx, "tcp", "model.test:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("already-canceled context was ignored: %v", err)
	}
}
