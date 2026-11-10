package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const modelConnectTimeout = 10 * time.Second

// modelTLSConnector races validated TLS, not TCP: no HTTP bytes reach a loser.
// Injected lookup/dial functions must honor their context, as the stdlib does.
// tlsConfig is immutable after construction and is only customized by tests.
type modelTLSConnector struct {
	lookup    func(context.Context, string, string) ([]netip.Addr, error)
	dial      func(context.Context, string, string) (net.Conn, error)
	tlsConfig *tls.Config
	timeout   time.Duration
}

// Transport deliberately detaches dialing from request cancellation. Preserve
// the original context as a value so our pending DNS/TCP/TLS race cancels too.
type modelRequestContextKey struct{}

type modelHTTPTransport struct {
	*http.Transport
}

func (t *modelHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, errors.New("Rewind model transport requires HTTPS")
	}
	ctx := context.WithValue(req.Context(), modelRequestContextKey{}, req.Context())
	return t.Transport.RoundTrip(req.WithContext(ctx))
}

func newModelHTTPClient() *http.Client {
	// One dialer serves both families; numeric candidates cannot trigger DNS
	// or the dialer's own delayed Happy Eyeballs race.
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	connector := &modelTLSConnector{
		lookup:  net.DefaultResolver.LookupNetIP,
		dial:    dialer.DialContext,
		timeout: modelConnectTimeout,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialTLSContext:        connector.dialTLSContext,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression:    true,
		MaxConnsPerHost:       16,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   modelConnectTimeout,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: &modelHTTPTransport{transport},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (d *modelTLSConnector) dialTLSContext(parent context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported model transport network %q", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, errors.New("model TLS target requires a host and port")
	}

	// This budget starts before resolution and is shared by every attempt.
	ctx, cancel := context.WithTimeout(parent, d.timeout)
	defer cancel()
	if requestCtx, ok := parent.Value(modelRequestContextKey{}).(context.Context); ok {
		if err := requestCtx.Err(); err != nil {
			return nil, err
		}
		stop := context.AfterFunc(requestCtx, cancel)
		defer stop()
		if deadline, ok := requestCtx.Deadline(); ok {
			var cancelDeadline context.CancelFunc
			ctx, cancelDeadline = context.WithDeadline(ctx, deadline)
			defer cancelDeadline()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var addresses []netip.Addr
	serverName := host
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
		serverName = literal.WithZone("").Unmap().String()
	} else {
		addresses, err = d.lookup(ctx, "ip", host)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("resolve model TLS host %q: %w", host, err)
		}
	}

	var families [2][]netip.Addr // IPv6 first, IPv4 in the same scheduling turn.
	seen := make(map[netip.Addr]bool)
	for _, ip := range addresses {
		if !ip.IsValid() {
			continue
		}
		ip = ip.Unmap()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		family := 0
		if ip.Is4() {
			family = 1
		}
		families[family] = append(families[family], ip)
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no IP addresses for model TLS host %q", host)
	}

	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.tlsConfig != nil {
		config = d.tlsConfig.Clone()
	}
	// SNI and certificate verification always use the target, not its candidate
	// address or an injected ServerName. HTTP/2 is not offered even in tests.
	config.ServerName = serverName
	config.NextProtos = []string{"http/1.1"}

	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	start := make(chan struct{})
	var workers sync.WaitGroup
	count := 0
	for i, candidates := range families {
		if len(candidates) == 0 {
			continue
		}
		count++
		workers.Add(1)
		go func(family int, candidates []netip.Addr) {
			defer workers.Done()
			<-start
			var failures []error
			for _, ip := range candidates {
				if ctx.Err() != nil {
					return
				}
				target := net.JoinHostPort(ip.String(), port)
				network := "tcp6"
				if family == 1 {
					network = "tcp4"
				}
				raw, err := d.dial(ctx, network, target)
				if err == nil && raw == nil {
					err = errors.New("dial returned no connection")
				}
				if err != nil {
					if raw != nil {
						raw.Close()
					}
					failures = append(failures, fmt.Errorf("dial %s: %w", target, err))
					continue
				}
				// A dial that finishes concurrently with cancellation is a loser.
				if ctx.Err() != nil {
					raw.Close()
					return
				}
				conn := tls.Client(raw, config)
				if err := conn.HandshakeContext(ctx); err != nil {
					raw.Close()
					failures = append(failures, fmt.Errorf("TLS %s: %w", target, err))
					continue
				}
				select {
				case results <- result{conn: conn}:
				case <-ctx.Done():
					// Do not wait to send a TLS close_notify to an unresponsive loser.
					raw.Close()
				}
				return
			}
			select {
			case results <- result{err: errors.Join(failures...)}:
			case <-ctx.Done():
			}
		}(i, candidates)
	}
	close(start)

	// Join all workers before returning: no pending handshake or late dial
	// retains a connection after a winner, deadline or cancellation is reported.
	defer workers.Wait()
	defer cancel() // Cancel before Wait (deferred calls run in reverse order).
	var failures []error
	for range count {
		select {
		case r := <-results:
			if ctx.Err() != nil {
				if r.conn != nil {
					// Close the socket without a potentially blocking TLS alert.
					r.conn.(*tls.Conn).NetConn().Close()
				}
				return nil, ctx.Err()
			}
			if r.conn != nil {
				return r.conn, nil
			}
			failures = append(failures, r.err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("no address established model TLS: %w", errors.Join(failures...))
}
