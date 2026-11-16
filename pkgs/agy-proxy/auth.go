package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var errCredentials = errors.New("credentials unavailable; sign in or refresh credentials")

type credential struct {
	AccessToken string
	Project     string
	Expiry      time.Time
}

type credentialSource interface {
	Load(context.Context) (credential, error)
}

// Keychain remains native-client-owned; only explicitly opted-in own files refresh here.
type localCredentials struct {
	file        string
	account     string
	refreshAgy  string
	refreshFile bool
	oauth       *oauthClient // Optional isolated test transport/endpoints.
	mu          sync.Mutex
}

func (s *localCredentials) Load(ctx context.Context) (credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return credential{}, errCredentials
	}
	if s.refreshFile {
		if s.file == "" || s.refreshAgy != "" {
			return credential{}, errCredentials
		}
		return s.loadOwnFile(ctx)
	}
	c, err := s.read(ctx)
	if err != nil {
		return credential{}, errCredentials
	}
	if c.Expiry.IsZero() || time.Until(c.Expiry) > time.Minute {
		return c, nil
	}
	if s.refreshAgy == "" || s.file != "" {
		return credential{}, errCredentials
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	// No shell, no generation, no forwarding of the proxy's diagnostic output.
	cmd := exec.CommandContext(refreshCtx, s.refreshAgy, "models")
	cmd.Env = withoutGateway(os.Environ())
	if cmd.Run() != nil {
		return credential{}, errCredentials
	}
	c, err = s.read(ctx)
	if err != nil || (!c.Expiry.IsZero() && time.Until(c.Expiry) <= time.Minute) {
		return credential{}, errCredentials
	}
	return c, nil
}

func (s *localCredentials) loadOwnFile(ctx context.Context) (credential, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	file, err := openPrivateCredentialFile(s.file)
	if err != nil {
		return credential{}, errCredentials
	}
	defer file.root.Close()
	unlock, err := file.lock(ctx)
	if err != nil {
		return credential{}, errCredentials
	}
	defer unlock()
	data, original, err := file.read()
	if err != nil {
		return credential{}, errCredentials
	}
	token, err := decodeOwnToken(data)
	if err != nil {
		return credential{}, errCredentials
	}
	if time.Until(token.Expiry) <= time.Minute {
		refreshCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		oauth := s.oauth
		if oauth == nil {
			return credential{}, errCredentials
		}
		token, err = oauth.refresh(refreshCtx, token.RefreshToken)
		if err != nil || refreshCtx.Err() != nil {
			return credential{}, errCredentials
		}
		current, err := file.existing()
		if err != nil {
			return credential{}, errCredentials
		}
		if !sameCredentialFile(original, current) {
			// A separately completed login takes precedence over this refresh.
			data, _, err = file.read()
			if err != nil {
				return credential{}, errCredentials
			}
			token, err = decodeOwnToken(data)
			if err != nil || time.Until(token.Expiry) <= time.Minute {
				return credential{}, errCredentials
			}
		} else if file.write(token, true, original) != nil {
			return credential{}, errCredentials
		}
	}
	return credential{AccessToken: token.AccessToken, Expiry: token.Expiry}, nil
}

func withoutGateway(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if key == "CLOUD_CODE_URL" || strings.HasPrefix(key, "AGY_LLM_GATEWAY_") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (s *localCredentials) read(ctx context.Context) (credential, error) {
	var data []byte
	var err error
	if s.file != "" {
		file, openErr := openCredentialFile(s.file, false)
		if openErr != nil {
			return credential{}, errCredentials
		}
		defer file.root.Close()
		data, _, err = file.read()
	} else {
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		data, err = exec.CommandContext(readCtx, "/usr/bin/security", "find-generic-password", "-s", "gemini", "-a", s.account, "-w").Output()
	}
	if err != nil {
		return credential{}, errCredentials
	}
	return decodeCredential(data)
}

func decodeCredential(data []byte) (credential, error) {
	data = []byte(strings.TrimSpace(string(data)))
	const prefix = "go-keyring-base64:"
	if strings.HasPrefix(string(data), prefix) {
		var err error
		data, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(string(data), prefix))
		if err != nil {
			return credential{}, errCredentials
		}
	}
	var envelope struct {
		Token      json.RawMessage `json:"token"`
		AuthMethod string          `json:"auth_method"`
		Project    string          `json:"project_id"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return credential{}, errCredentials
	}
	if len(envelope.Token) != 0 {
		// Only the captured consumer path has been verified, not enterprise auth.
		if envelope.AuthMethod != "consumer" {
			return credential{}, errCredentials
		}
		data = envelope.Token
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Expiry      string `json:"expiry"`
		Expired     string `json:"expired"`
		Project     string `json:"project_id"`
	}
	if json.Unmarshal(data, &token) != nil || token.AccessToken == "" || strings.ContainsAny(token.AccessToken, " \r\n\t") || (token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer")) {
		return credential{}, errCredentials
	}
	c := credential{AccessToken: token.AccessToken, Project: token.Project}
	if c.Project == "" {
		c.Project = envelope.Project
	}
	if token.Expiry == "" {
		token.Expiry = token.Expired
	}
	if token.Expiry != "" {
		var err error
		c.Expiry, err = time.Parse(time.RFC3339Nano, token.Expiry)
		if err != nil {
			return credential{}, errCredentials
		}
	}
	return c, nil
}
