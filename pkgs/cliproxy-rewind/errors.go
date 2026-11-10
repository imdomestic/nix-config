package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type problem struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status"`
	RequestID  string `json:"request_id,omitempty"`
}

func (p *problem) Error() string { return p.Message }
func fail(status int, code, message string) *problem {
	return &problem{Code: code, Message: message, HTTPStatus: status}
}

var requestIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

func unknownModelOutcome() *problem {
	return fail(503, "REWIND_REQUEST_OUTCOME_UNKNOWN", "Rewind request may already have executed; the result is unknown. Do not automatically retry; check task progress first")
}

// CPA recognizes stream_truncated as availability-neutral and forbids replay.
func routingProblem(p *problem) *problem {
	if p == nil || p.Code != "REWIND_REQUEST_OUTCOME_UNKNOWN" {
		return p
	}
	copy := *p
	copy.Code = "stream_truncated"
	copy.Message = "REWIND_REQUEST_OUTCOME_UNKNOWN: " + p.Message
	return &copy
}

type wireError struct {
	Code, Type, Stage, Reason, Origin string
	MinimumVersion                    string `json:"minimum_version"`
	Schema                            string `json:"diagnostic_schema"`
	RequestID                         string `json:"request_id"`
	ServerTime                        string `json:"server_time"`
	HTTPStatus                        int    `json:"http_status"`
}

func serviceProblem(status int, e wireError) *problem {
	if e.Schema != "rewind.auth-diagnostic.v1" || e.HTTPStatus != status || !requestIDPattern.MatchString(e.RequestID) || !strings.HasSuffix(e.ServerTime, "Z") {
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, e.ServerTime); err != nil {
		return nil
	}
	if e.Origin == "token" && status == 401 && e.Code == "REWIND_INTERNAL_AUTH_DENIED" && e.Stage == "service_assertion" {
		for _, reason := range strings.Fields("peer_invalid verifier_unavailable assertion_envelope_invalid assertion_signature_invalid assertion_expired assertion_not_yet_valid assertion_claims_invalid assertion_request_mismatch assertion_body_mismatch assertion_replayed replay_store_unavailable unknown") {
			if e.Reason == reason {
				return fail(status, "REWIND_INTERNAL_AUTH_DENIED", "Rewind internal service authorization failed; this does not indicate an invalid API key")
			}
		}
		return nil
	}
	if e.Origin != "service" || e.Code != map[int]string{401: "REWIND_AUTH_DENIED", 403: "REWIND_EXCLUSIVE_KEY_REQUIRED", 503: "REWIND_AUTH_UNAVAILABLE"}[status] {
		return nil
	}
	if (e.Stage == "authentication" || e.Stage == "key_authorization") && e.Reason == "unknown" && status == 503 {
		return fail(status, "rewind_upstream", "Rewind identity service is unavailable; existing device identity has been preserved")
	}
	if e.Stage == "authentication" && e.Reason == "unknown" {
		return fail(status, "rewind_auth_denied", "Rewind request authorization was not confirmed; verify the connection or contact support")
	}
	for _, entry := range []struct{ stage, reason, code, message string }{
		{"session_token", "jwt_expired", "REWIND_SESSION_TOKEN_EXPIRED", "Rewind device session token expired; no API key replacement is needed"},
		{"session_token", "jwt_invalid", "REWIND_SESSION_TOKEN_INVALID", "Rewind device session token failed validation; check the session without resetting the device"},
		{"session_binding", "binding_inactive", "REWIND_SESSION_BINDING_INACTIVE", "Rewind device session binding is inactive or inconsistent"},
		{"request_arrival", "arrival_invalid", "REWIND_REQUEST_ARRIVAL_INVALID", "Rewind request arrival validation failed; check the clock or contact support"},
		{"device_proof", "proof_invalid", "REWIND_DEVICE_PROOF_INVALID", "Rewind device proof failed validation; the device identity has not been reset"},
		{"proof_replay", "replay_rejected", "REWIND_PROOF_REPLAY_REJECTED", "Rewind rejected a repeated device proof; do not replay the same request"},
		{"key_authorization", "unknown", "REWIND_KEY_AUTHORIZATION_DENIED", "Rewind key authorization was not confirmed; check usage eligibility with the administrator"},
	} {
		if e.Stage == entry.stage && e.Reason == entry.reason && (status == 401 || (status == 403 && entry.stage == "key_authorization")) {
			return fail(status, entry.code, entry.message)
		}
	}
	return nil
}

func upstreamProblem(status int, headers http.Header, raw []byte) *problem {
	var v struct {
		Code  string    `json:"code"`
		Error wireError `json:"error"`
	}
	if len(raw) <= 65536 {
		_ = json.Unmarshal(raw, &v)
	}
	codes := []string{strings.ToLower(v.Code), strings.ToLower(v.Error.Code), strings.ToLower(v.Error.Type)}
	has := func(list string) bool {
		for _, code := range codes {
			for _, known := range strings.Fields(list) {
				if code == known {
					return true
				}
			}
		}
		return false
	}
	var p *problem
	switch {
	case status == 426:
		message := "Rewind requires a newer client protocol (current " + appVersion + ")"
		if clientVersionPattern.MatchString(v.Error.MinimumVersion) {
			message += "; minimum " + v.Error.MinimumVersion
		}
		p = fail(426, "rewind_update_required", message)
	case has("rewind_request_outcome_unknown request_outcome_unknown"):
		p = unknownModelOutcome()
	case serviceProblem(status, v.Error) != nil:
		p = serviceProblem(status, v.Error)
	case status == 403 && headers.Get("X-Rewind-Auth-Error") == "REWIND_EXCLUSIVE_KEY_REQUIRED":
		p = fail(403, "REWIND_EXCLUSIVE_KEY_REQUIRED", "This API key is not authorized for Rewind; check usage eligibility with the administrator")
	case status == 402 || has("insufficient_quota insufficient_balance balance_insufficient quota_exceeded quota_exhausted api_key_quota_exhausted key_quota_exceeded"):
		p = fail(402, "insufficient_quota", "Rewind quota exhausted")
	case has("context_length_exceeded context_window_exceeded context_window_overflow max_context_length_exceeded"):
		p = fail(400, "context_window_exceeded", "Rewind context window exceeded; reduce input or compact the conversation")
	case has("too_many_images image_limit_exceeded image_count_exceeded max_images_exceeded input_image_limit_exceeded"):
		p = fail(400, "image_limit_exceeded", "Rewind image limit exceeded; reduce attachments")
	case status == 429 || has("rate_limit_exceeded rate_limit_error"):
		p = fail(429, "rate_limit_exceeded", "Rewind rate limit exceeded")
	case status == 401 && v.Error.Stage == "upstream_http" && v.Error.Code == "authentication_error" && v.Error.Type == "authentication_error" && requestIDPattern.MatchString(v.Error.RequestID):
		p = fail(401, "upstream_auth", "Rewind upstream model authorization failed; this does not indicate an invalid Rewind API key")
	case status == 403 && v.Error.Stage == "upstream_http" && v.Error.Code == "permission_denied" && v.Error.Type == "permission_error" && requestIDPattern.MatchString(v.Error.RequestID):
		p = fail(403, "upstream_permission", "Rewind upstream model permission denied; no Rewind API key replacement is needed")
	case status == 401 || status == 403:
		p = fail(status, "rewind_auth_denied", "Rewind request authorization was not confirmed; verify the connection or contact support")
	case status == 404:
		p = fail(404, "rewind_api_not_found", "Rewind API endpoint is unavailable")
	case status == 413 || has("request_too_large payload_too_large"):
		p = fail(413, "invalid_request_error", "Rewind request is too large; reduce input and attachments")
	case status == 400 || status == 422 || has("invalid_request_error invalid_request"):
		p = fail(status, "invalid_request_error", "Rewind rejected the request; check model parameters and input size")
	default:
		if status < 400 || status > 599 {
			status = 502
		}
		p = fail(status, "rewind_upstream", "Rewind upstream unavailable")
	}
	id := v.Error.RequestID
	if !requestIDPattern.MatchString(id) {
		id = headers.Get("X-Rewind-Request-Id")
	}
	if requestIDPattern.MatchString(id) {
		p.RequestID = id
		p.Message += " (request " + id + ")"
	}
	return p
}

func eventProblem(raw []byte) *problem {
	var v struct {
		Code, Type string
		Error      wireError
	}
	_ = json.Unmarshal(raw, &v)
	status := v.Error.HTTPStatus
	if serviceProblem(status, v.Error) == nil {
		status = 502
		for _, code := range []string{v.Error.Type, v.Error.Code, v.Code} {
			switch strings.ToLower(code) {
			case "authentication_error":
				status = 401
			case "permission_error":
				status = 403
			case "rate_limit_exceeded", "rate_limit_error", "capacity", "overloaded":
				status = 429
			}
		}
	}
	return upstreamProblem(status, nil, raw)
}
