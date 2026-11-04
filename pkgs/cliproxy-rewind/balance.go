package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const balanceConfigEnv = "CLIPROXY_REWIND_BALANCE_CONFIG"
const balancePath = "/rewind/balance"
const balanceUsagePath = "/api/v1/rewind/usage"

var balanceAmountPattern = regexp.MustCompile(`^\d{1,12}(?:\.\d{1,8})?$`)
var tailscaleIPv4 = netip.MustParsePrefix("100.64.0.0/10")
var tailscaleIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

type balanceConfig struct {
	ListenAddress string `json:"listen_address"`
	Port          int    `json:"port"`
	ClientKeyFile string `json:"client_key_file"`
	APIKeyFile    string `json:"api_key_file"`
	DeviceFile    string `json:"device_file"`
}

type balanceResponse struct {
	Schema       string  `json:"schema"`
	Currency     string  `json:"currency"`
	AvailableUSD *string `json:"available_usd"`
	Exhausted    bool    `json:"exhausted"`
	AsOf         string  `json:"as_of"`
}

type balanceFetch struct {
	identity [sha256.Size]byte
	config   balanceConfig
	done     chan struct{}
	cancel   context.CancelFunc
	once     sync.Once
}

func (f *balanceFetch) finish() { f.once.Do(func() { close(f.done) }) }

type balanceService struct {
	mu      sync.Mutex
	workers sync.WaitGroup
	closed  bool

	config balanceConfig
	ctx    context.Context
	cancel context.CancelFunc
	now    func() time.Time
	fetch  func(context.Context, balanceConfig) ([]byte, *problem)

	identity      [sha256.Size]byte
	identityValid bool
	cached        []byte
	cacheUntil    time.Time
	inflight      *balanceFetch
	failureUntil  time.Time
	failureDelay  time.Duration
}

func newBalanceService(config balanceConfig) *balanceService {
	ctx, cancel := context.WithCancel(context.Background())
	return &balanceService{config: config, ctx: ctx, cancel: cancel, now: time.Now, fetch: fetchBalance}
}

func (s *balanceService) reconfigure(config balanceConfig) {
	s.mu.Lock()
	if s.config == config {
		s.mu.Unlock()
		return
	}
	s.config = config
	s.cached = nil
	s.cacheUntil = time.Time{}
	s.identityValid = false
	s.failureUntil = time.Time{}
	s.failureDelay = 0
	inflight := s.inflight
	s.inflight = nil
	s.mu.Unlock()
	if inflight != nil {
		inflight.cancel()
	}
}

func (s *balanceService) stop() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	// Cancellation alone must not leave Go callbacks running after plugin quiescence.
	s.workers.Wait()
}

func (s *balanceService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != balancePath || r.URL.RawPath != "" || r.RequestURI != balancePath {
		writeBalanceError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeBalanceError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeBalanceError(w, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	config := s.config
	s.mu.Unlock()
	if !authorizeBalanceRequest(r, config.ClientKeyFile) {
		writeBalanceError(w, http.StatusUnauthorized)
		return
	}
	identity, err := balanceIdentity(config)
	if err != nil {
		writeBalanceError(w, http.StatusServiceUnavailable)
		return
	}
	raw, status := s.get(r.Context(), identity, config)
	if status != 0 {
		writeBalanceError(w, status)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func writeBalanceError(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"balance unavailable"}`)
}

func authorizeBalanceRequest(r *http.Request, path string) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(values[0], "Bearer ")
	if provided == "" || strings.ContainsAny(provided, " \t\r\n") {
		return false
	}
	raw, err := readBoundedFile(path, 8<<10)
	key := strings.TrimSpace(string(raw))
	if err != nil || key == "" || strings.ContainsAny(key, " \t\r\n") {
		return false
	}
	providedHash, keyHash := sha256.Sum256([]byte(provided)), sha256.Sum256([]byte(key))
	return subtle.ConstantTimeCompare(providedHash[:], keyHash[:]) == 1
}

func balanceIdentity(config balanceConfig) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	apiKey, err := readBoundedFile(config.APIKeyFile, 8<<10)
	if err != nil {
		return zero, err
	}
	key := strings.TrimSpace(string(apiKey))
	if key == "" || strings.ContainsAny(key, " \t\r\n") {
		return zero, errors.New("invalid API key")
	}
	device, err := readBoundedFile(config.DeviceFile, 64<<10)
	if err != nil {
		return zero, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(config.APIKeyFile))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(key))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(config.DeviceFile))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(device)
	var identity [sha256.Size]byte
	copy(identity[:], h.Sum(nil))
	return identity, nil
}

func (s *balanceService) get(requestContext context.Context, identity [sha256.Size]byte, config balanceConfig) ([]byte, int) {
	for {
		if requestContext.Err() != nil || s.ctx.Err() != nil {
			return nil, http.StatusServiceUnavailable
		}
		currentIdentity, err := balanceIdentity(config)
		if err != nil || currentIdentity != identity {
			return nil, http.StatusServiceUnavailable
		}
		now := s.now()
		s.mu.Lock()
		if s.closed || s.config != config {
			s.mu.Unlock()
			return nil, http.StatusServiceUnavailable
		}
		if !s.identityValid || s.identity != identity {
			old := s.inflight
			s.identity, s.identityValid = identity, true
			s.cached = nil
			s.cacheUntil = time.Time{}
			s.failureUntil = time.Time{}
			s.failureDelay = 0
			s.inflight = nil
			if old != nil {
				old.cancel()
			}
		}
		if len(s.cached) != 0 && now.Before(s.cacheUntil) {
			raw := bytes.Clone(s.cached)
			s.mu.Unlock()
			return raw, 0
		}
		if now.Before(s.failureUntil) {
			s.mu.Unlock()
			return nil, http.StatusServiceUnavailable
		}
		if s.inflight == nil {
			ctx, cancel := context.WithCancel(s.ctx)
			fetch := &balanceFetch{identity: identity, config: config, done: make(chan struct{}), cancel: cancel}
			s.inflight = fetch
			s.workers.Add(1)
			go s.runFetch(ctx, fetch)
		}
		done := s.inflight.done
		s.mu.Unlock()
		select {
		case <-done:
		case <-requestContext.Done():
			return nil, http.StatusServiceUnavailable
		case <-s.ctx.Done():
			return nil, http.StatusServiceUnavailable
		}
	}
}

func (s *balanceService) runFetch(parent context.Context, fetch *balanceFetch) {
	defer s.workers.Done()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	raw, problem := s.fetch(ctx, fetch.config)
	cancel()
	identity, identityErr := balanceIdentity(fetch.config)
	if identityErr != nil || identity != fetch.identity {
		problem = fail(503, "rewind_balance_identity", "Rewind balance identity changed")
		raw = nil
	}

	s.mu.Lock()
	if s.inflight == fetch {
		s.inflight = nil
		if problem == nil {
			s.cached = bytes.Clone(raw)
			s.cacheUntil = s.now().Add(60 * time.Second)
			s.failureUntil = time.Time{}
			s.failureDelay = 0
		} else {
			s.cached = nil
			s.cacheUntil = time.Time{}
			if s.failureDelay == 0 {
				s.failureDelay = time.Second
			} else {
				s.failureDelay *= 2
				if s.failureDelay > 30*time.Second {
					s.failureDelay = 30 * time.Second
				}
			}
			s.failureUntil = s.now().Add(s.failureDelay)
		}
	}
	s.mu.Unlock()
	fetch.finish()
}

func fetchBalance(ctx context.Context, config balanceConfig) ([]byte, *problem) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client := getClient(credential{Type: "rewind", APIKeyFile: config.APIKeyFile, DeviceFile: config.DeviceFile})
	url := client.origin + balanceUsagePath
	headers, err := client.requestHeaders(ctx, http.MethodGet, url, nil, false)
	if err != nil {
		return nil, err
	}
	headers.Set("Accept", "application/json")
	req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if requestErr != nil {
		return nil, fail(500, "rewind_balance", "Invalid Rewind balance endpoint")
	}
	req.Header = headers
	res, requestErr := client.client.Do(req)
	if requestErr != nil {
		return nil, fail(502, "rewind_balance_unavailable", "Rewind balance unavailable")
	}
	defer res.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if readErr != nil || len(raw) > 64<<10 {
		return nil, fail(502, "rewind_balance_unavailable", "Invalid Rewind balance response")
	}
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			client.invalidate()
		}
		return nil, fail(502, "rewind_balance_unavailable", "Rewind balance unavailable")
	}
	normalized, normalizeErr := normalizeBalance(raw)
	if normalizeErr != nil {
		return nil, fail(502, "rewind_balance_unavailable", "Invalid Rewind balance response")
	}
	return normalized, nil
}

func normalizeBalance(raw []byte) ([]byte, error) {
	var upstream struct {
		Schema       string          `json:"schema"`
		Currency     string          `json:"currency"`
		AvailableUSD json.RawMessage `json:"available_usd"`
		Exhausted    *bool           `json:"exhausted"`
		AsOf         string          `json:"as_of"`
	}
	if json.Unmarshal(raw, &upstream) != nil || upstream.Schema != "rewind.quota.v1" || upstream.Currency != "USD" || upstream.Exhausted == nil {
		return nil, errors.New("invalid quota schema")
	}
	if _, err := time.Parse(time.RFC3339, upstream.AsOf); err != nil {
		return nil, errors.New("invalid quota timestamp")
	}
	var available *string
	switch {
	case bytes.Equal(upstream.AvailableUSD, []byte("null")):
	case len(upstream.AvailableUSD) != 0:
		var amount string
		if json.Unmarshal(upstream.AvailableUSD, &amount) != nil || !balanceAmountPattern.MatchString(amount) {
			return nil, errors.New("invalid quota amount")
		}
		available = &amount
	default:
		return nil, errors.New("missing quota amount")
	}
	exhausted := available != nil && decimalIsZero(*available)
	if *upstream.Exhausted != exhausted {
		return nil, errors.New("inconsistent quota exhaustion")
	}
	return json.Marshal(balanceResponse{Schema: "rewind.balance.v1", Currency: "USD", AvailableUSD: available, Exhausted: exhausted, AsOf: upstream.AsOf})
}

func decimalIsZero(value string) bool {
	for _, r := range value {
		if r != '0' && r != '.' {
			return false
		}
	}
	return true
}

type balanceListener struct {
	config      balanceConfig
	endpoint    string
	service     *balanceService
	server      *http.Server
	listener    net.Listener
	done        chan struct{}
	connections sync.WaitGroup
}

func (l *balanceListener) connectionState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		l.connections.Add(1)
	case http.StateClosed, http.StateHijacked:
		l.connections.Done()
	}
}

func (l *balanceListener) stop(timeout time.Duration) {
	l.service.stop()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = l.server.Shutdown(ctx)
	// Shutdown can time out on partial headers; Close also interrupts accepted sockets.
	_ = l.server.Close()
	_ = l.listener.Close()
	<-l.done
	// Serve has stopped accepting before Wait, so no new StateNew callback can race it.
	l.connections.Wait()
}

var balanceRuntimeMu sync.Mutex
var balanceConfigureMu sync.Mutex
var currentBalanceListener *balanceListener

func configureBalance() *problem {
	balanceConfigureMu.Lock()
	defer balanceConfigureMu.Unlock()
	path := os.Getenv(balanceConfigEnv)
	if path == "" {
		balanceRuntimeMu.Lock()
		old := currentBalanceListener
		currentBalanceListener = nil
		balanceRuntimeMu.Unlock()
		if old != nil {
			old.stop(2 * time.Second)
		}
		return nil
	}
	config, endpoint, err := loadBalanceConfig(path)
	if err != nil {
		return fail(400, "rewind_balance_config", "Invalid Rewind balance configuration")
	}

	balanceRuntimeMu.Lock()
	if currentBalanceListener != nil && currentBalanceListener.endpoint == endpoint {
		currentBalanceListener.service.reconfigure(config)
		balanceRuntimeMu.Unlock()
		return nil
	}
	balanceRuntimeMu.Unlock()

	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		return fail(503, "rewind_balance_listener", "Cannot start Rewind balance listener")
	}
	service := newBalanceService(config)
	server := &http.Server{Handler: service, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	started := &balanceListener{config: config, endpoint: endpoint, service: service, server: server, listener: listener, done: make(chan struct{})}
	server.ConnState = started.connectionState
	go func() {
		defer close(started.done)
		_ = server.Serve(listener)
	}()

	balanceRuntimeMu.Lock()
	old := currentBalanceListener
	currentBalanceListener = started
	balanceRuntimeMu.Unlock()
	if old != nil {
		old.stop(2 * time.Second)
	}
	return nil
}

func stopBalanceListener() {
	balanceConfigureMu.Lock()
	defer balanceConfigureMu.Unlock()
	balanceRuntimeMu.Lock()
	listener := currentBalanceListener
	currentBalanceListener = nil
	balanceRuntimeMu.Unlock()
	if listener != nil {
		listener.stop(2 * time.Second)
	}
}

func loadBalanceConfig(path string) (balanceConfig, string, error) {
	var config balanceConfig
	if !filepath.IsAbs(path) {
		return config, "", errors.New("configuration path must be absolute")
	}
	raw, err := readBoundedFile(path, 64<<10)
	if err != nil {
		return config, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return config, "", errors.New("invalid configuration JSON")
	}
	if config.ListenAddress == "" || config.Port < 1 || config.Port > 65535 || !filepath.IsAbs(config.ClientKeyFile) || !filepath.IsAbs(config.APIKeyFile) || !filepath.IsAbs(config.DeviceFile) {
		return config, "", errors.New("invalid configuration fields")
	}
	address, err := safeListenAddress(config.ListenAddress)
	if err != nil {
		return config, "", err
	}
	return config, net.JoinHostPort(address, strconv.Itoa(config.Port)), nil
}

func safeListenAddress(host string) (string, error) {
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\") {
		return "", errors.New("invalid listen address")
	}
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = append(addresses, literal)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resolved, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
		cancel()
		if lookupErr != nil || len(resolved) == 0 {
			return "", errors.New("cannot resolve listen address")
		}
		for _, item := range resolved {
			address, ok := netip.AddrFromSlice(item.IP)
			if !ok {
				return "", errors.New("invalid resolved address")
			}
			addresses = append(addresses, address.Unmap())
		}
	}
	selected := netip.Addr{}
	for _, address := range addresses {
		address = address.Unmap()
		if address.Zone() != "" || address.IsUnspecified() || !(address.IsLoopback() || tailscaleIPv4.Contains(address) || tailscaleIPv6.Contains(address)) {
			return "", fmt.Errorf("unsafe listen address %s", address)
		}
		if !selected.IsValid() || address.Is4() {
			selected = address
		}
	}
	if !selected.IsValid() {
		return "", errors.New("no safe listen address")
	}
	return selected.String(), nil
}
