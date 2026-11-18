package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type mediaTransportError struct {
	calls      atomic.Int32
	replayable atomic.Bool
}

func (transport *mediaTransportError) RoundTrip(r *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	transport.replayable.Store(r.GetBody != nil)
	return nil, errors.New("google-private secret-refresh-token " + testKey)
}

func TestMediaTransportErrorsNeverLeakOrReplay(t *testing.T) {
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected HTTP request") }, fixedCredentials{credential{AccessToken: "google-private", Project: "p"}})
	transport := &mediaTransportError{}
	p.client.Transport = transport
	w := mediaDo(p, "/v1/images/generations", "application/json", strings.NewReader(mediaImageJSON))
	if w.Code != 502 || transport.calls.Load() != 1 || transport.replayable.Load() {
		t.Fatalf("transport error got %d, attempts=%d", w.Code, transport.calls.Load())
	}
	for _, secret := range []string{"google-private", "secret-refresh-token", testKey} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("transport diagnostic leaked")
		}
	}
}

func TestMediaSessionValidationBeforeCredentials(t *testing.T) {
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid session reached upstream") }, mediaBadSource{})
	for _, headers := range []map[string]string{
		{"X-Agy-Session-Id": "one", "X-Session-Id": "two"},
		{"X-Agy-Session-Id": strings.Repeat("a", 257)},
		{"X-Agy-Request-Id": strings.Repeat("a", 513)},
		{"X-Agy-Request-Id": "private\r\nsecret-token"},
	} {
		r := httptest.NewRequest("POST", "/v1/images/generations", strings.NewReader(mediaImageJSON))
		r.Header.Set("Authorization", "Bearer "+testKey)
		r.Header.Set("Content-Type", "application/json")
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		p.mediaRoute(w, r)
		if w.Code != 400 || strings.Contains(w.Body.String(), "secret-token") {
			t.Fatalf("invalid session: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestMediaMultipartEpilogueAndTransferEncoding(t *testing.T) {
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid multipart reached upstream") }, fixedCredentials{})
	kind, body := mediaForm(t, mediaField("model", "gemini-3.1-flash-image"), mediaField("prompt", "edit"), mediaTestPart{"image", "x.png", "image/png", mediaPNGBytes(t)})
	data, _ := io.ReadAll(body)
	p.maxBody = int64(len(data) + 128)
	withEpilogue := append(append([]byte{}, data...), bytes.Repeat([]byte("x"), 8192)...)
	if w := mediaDo(p, "/v1/images/edits", kind, bytes.NewReader(withEpilogue)); w.Code != 413 {
		t.Fatalf("oversized epilogue got %d", w.Code)
	}
	p.maxBody = 1 << 20
	encoded := bytes.Replace(data, []byte("Content-Type: image/png\r\n"), []byte("Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n"), 1)
	if w := mediaDo(p, "/v1/images/edits", kind, bytes.NewReader(encoded)); w.Code != 400 {
		t.Fatalf("unhandled transfer encoding got %d", w.Code)
	}
}

func TestMediaResponseImageByteLimitAndUnwrappedOutput(t *testing.T) {
	// One extra decoded byte can still have the same encoded length as the cap.
	tooLarge := make([]byte, mediaMaxFile+1)
	copy(tooLarge, mediaPNGBytes(t))
	if _, _, err := decodeMediaResponse(mediaNative(mediaInline(mediaFile{"image/png", tooLarge})), true); err == nil {
		t.Fatal("oversized returned image was accepted")
	}
	var outer struct{ Response json.RawMessage }
	if json.Unmarshal(mediaNative(mediaImagePart()), &outer) != nil {
		t.Fatal("invalid fixture")
	}
	_, images, err := decodeMediaResponse(outer.Response, true)
	if err != nil || len(images) != 1 || !bytes.Equal(images[0].data, mediaPNGBytes(t)) {
		t.Fatal("unwrapped native output was not parsed")
	}
}

func TestMediaImageAspectAndSizeMappings(t *testing.T) {
	for _, ratio := range strings.Fields("1:1 2:3 3:2 3:4 4:3 4:5 5:4 9:16 16:9 21:9") {
		input, err := mediaImageInput(map[string]string{"model": "gemini-3.1-flash-image", "prompt": "draw", "aspect_ratio": ratio}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			Config struct {
				Image map[string]string `json:"imageConfig"`
			} `json:"generationConfig"`
		}
		if json.Unmarshal(input.gemini, &request) != nil || request.Config.Image["aspectRatio"] != ratio {
			t.Fatal("aspect ratio not mapped")
		}
	}
	for size, native := range map[string]string{"1024x1024": "1K", "2048x2048": "2K", "4096x4096": "4K"} {
		input, err := mediaImageInput(map[string]string{"model": "gemini-3.1-flash-image", "prompt": "draw", "size": size}, nil)
		if err != nil || !bytes.Contains(input.gemini, []byte(`"imageSize":"`+native+`"`)) {
			t.Fatal("square size not mapped")
		}
	}
}

func TestMediaServeHTTPEnabledRoutes(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		data, _ := io.ReadAll(r.Body)
		if bytes.Contains(data, []byte(`"IMAGE"`)) {
			_, _ = w.Write(mediaNative(mediaImagePart()))
		} else {
			_, _ = w.Write(mediaNative(map[string]string{"text": "actual transcript"}))
		}
	}, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
	p.openaiCompat = true
	for _, route := range []string{"/v1/images/generations", "/v1/images/edits", "/v1/audio/transcriptions", "/v1/audio/translations"} {
		kind, body := "application/json", io.Reader(strings.NewReader(mediaImageJSON))
		if route == "/v1/images/edits" {
			kind, body = mediaForm(t, mediaField("model", "gemini-3.1-flash-image"), mediaField("prompt", "edit"), mediaTestPart{"image", "x.png", "image/png", mediaPNGBytes(t)})
		} else if strings.HasPrefix(route, "/v1/audio/") {
			kind, body = mediaForm(t, mediaField("model", "gemini-2.5-flash"), mediaTestPart{"file", "x.wav", "audio/wav", mediaWAV()})
		}
		r := httptest.NewRequest("POST", route, body)
		r.Header.Set("Authorization", "Bearer "+testKey)
		r.Header.Set("Content-Type", kind)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("enabled %s returned %d: %s", route, w.Code, w.Body.String())
		}
	}
	if calls.Load() != 4 {
		t.Fatal("enabled media routes were not dispatched")
	}
}

type mediaCanceledSource struct{}

func (mediaCanceledSource) Load(ctx context.Context) (credential, error) {
	if ctx.Err() == nil {
		return credential{}, errors.New("expected canceled credentials context")
	}
	return credential{}, ctx.Err()
}

func TestMediaCanceledCredentialLookup(t *testing.T) {
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Error("canceled credentials reached upstream") }, mediaCanceledSource{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/v1/images/generations", strings.NewReader(mediaImageJSON)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testKey)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.mediaRoute(w, r)
	if w.Code != 503 {
		t.Fatalf("canceled lookup got %d", w.Code)
	}
}
