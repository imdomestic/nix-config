package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestResponsesMultimodalFunctionOutputs(t *testing.T) {
	_, output, history := responsesTestReplayFixture(t)
	results := responsesTestResults(output)
	results[0].(map[string]any)["output"] = []any{
		map[string]any{"type": "input_text", "text": "before "},
		map[string]any{"type": "input_image", "image_url": "data:image/png;base64,aGk=", "detail": "auto"},
		map[string]any{"type": "input_text", "text": " after"},
	}
	history = append(history, results...)
	input, err := responsesDecodeRequest(chatRaw(responsesTestReplayRequest(history)), testKey)
	if err != nil {
		t.Fatal(err)
	}
	native := responsesTestMap(t, input.Gemini)
	response := native["contents"].([]any)[2].(map[string]any)["parts"].([]any)[0].(map[string]any)["functionResponse"].(map[string]any)
	if response["response"].(map[string]any)["result"] != "before [image 1] after" || len(response["parts"].([]any)) != 1 {
		t.Fatal("multimodal function response lost text, image position labels, or image parts")
	}
	for _, bad := range []any{
		[]any{map[string]any{"type": "input_video", "video_url": "data:video/mp4;base64,aGk="}},
		[]any{map[string]any{"type": "input_audio", "input_audio": map[string]any{"data": "aGk=", "format": "wav"}}},
		[]any{map[string]any{"type": "input_image", "image_url": "https://internal.invalid/x"}},
	} {
		results[0].(map[string]any)["output"] = bad
		if _, err := responsesDecodeRequest(chatRaw(responsesTestReplayRequest(history)), testKey); err == nil {
			t.Fatal("unsupported media tool result accepted")
		}
	}
}

func TestResponsesSDKEventAccumulatorReplaysTerminalItems(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":[{"role":"user","content":"hi"}],"stream":true,"include":["reasoning.encrypted_content"]}`)
	native := responsesTestSSE(
		`{"candidates":[{"content":{"parts":[{"text":"first"},{"thought":true,"text":"explanation"}]}}]}`,
		`{"candidates":[{"content":{"parts":[{"text":" second"},{"functionCall":{"name":"f","args":{"id":9007199254740993}}}]},"finishReason":"STOP"}]}`,
	)
	var stream bytes.Buffer
	if err := responsesConvertStream(&stream, strings.NewReader(native), input, testKey, "resp_sdk", 1, responsesTestLimit, nil); err != nil {
		t.Fatal(err)
	}
	// SDKs commonly build history from item.done rather than response.completed.
	items := map[int]map[string]any{}
	for _, event := range responsesTestEvents(t, stream.String()) {
		if event["type"] != "response.output_item.done" {
			continue
		}
		index, _ := event["output_index"].(json.Number).Int64()
		items[int(index)] = event["item"].(map[string]any)
	}
	history := []any{map[string]any{"role": "user", "content": "hi"}}
	for i := 0; i < len(items); i++ {
		history = append(history, items[i])
	}
	history = append(history, map[string]any{"type": "function_call_output", "call_id": items[2]["call_id"], "output": `{"ok":true}`})
	next, err := responsesDecodeRequest(chatRaw(map[string]any{"model": "gemini-test", "input": history, "store": false}), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(next.Gemini), "9007199254740993") || !strings.Contains(string(next.Gemini), "first second") {
		// Native text boundaries must not be merged, so compare concatenated values.
		native := responsesTestMap(t, next.Gemini)
		parts := native["contents"].([]any)[1].(map[string]any)["parts"].([]any)
		var text string
		for _, raw := range parts {
			part := raw.(map[string]any)
			if part["thought"] != true {
				value, _ := part["text"].(string)
				text += value
			}
		}
		if text != "first second" || !strings.Contains(string(next.Gemini), "9007199254740993") {
			t.Fatal("SDK item accumulator lost text or integer")
		}
	}
}

func TestResponsesSSEFramingIncompleteAndUsage(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi","stream":true,"include":["reasoning.encrypted_content"]}`)
	frame := `{"response":{"candidates":[{"content":{"parts":[{"text":"partial"}]},"finishReason":"MAX_TOKENS"}]}}`
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		// Multiline data with comments and ignored SSE fields remains valid JSON.
		native := "\ufeff: comment\nid: ignored\ndata: {\n: middle\ndata: " + strings.TrimPrefix(frame, "{") + "\n\n" + responsesTestSSE("[DONE]")
		native = strings.ReplaceAll(native, "\n", ending)
		var out bytes.Buffer
		if err := responsesConvertStream(&out, &responsesTestByteReader{value: native}, input, testKey, "resp_framing", 1, responsesTestLimit, nil); err != nil {
			t.Fatal(err)
		}
		events := responsesTestEvents(t, out.String())
		if events[len(events)-1]["type"] != "response.incomplete" {
			t.Fatal("MAX_TOKENS did not end with incomplete")
		}
		response := events[len(events)-1]["response"].(map[string]any)
		if response["incomplete_details"].(map[string]any)["reason"] != "max_output_tokens" {
			t.Fatal("wrong incomplete reason")
		}
	}
	// Aggregate source bytes are bounded even for individually tiny comments.
	var dst bytes.Buffer
	reader := io.LimitReader(strings.NewReader(strings.Repeat(": comment\n\n", 1000)), 4000)
	if err := responsesConvertStream(&dst, reader, input, testKey, "resp_limit", 1, 2048, nil); err == nil || strings.Contains(dst.String(), "response.completed") {
		t.Fatal("comment stream aggregate bound ignored")
	}
}

func TestResponsesSignatureOnlyCarrierAndNoEncryptionOptIn(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi","include":["reasoning.encrypted_content"]}`)
	out := responsesTestJSON(t, input, `{"candidates":[{"content":{"parts":[{"thought":true,"thoughtSignature":"only","futureCarrier":{"n":9007199254740993}}]},"finishReason":"STOP"}]}`)
	history := []any{map[string]any{"role": "user", "content": "hi"}}
	history = append(history, out["output"].([]any)...)
	history = append(history, map[string]any{"role": "user", "content": "next"})
	if _, err := responsesDecodeRequest(chatRaw(map[string]any{"model": "gemini-test", "input": history}), testKey); err != nil {
		t.Fatal(err)
	}
	input.Encrypted = false
	out = responsesTestJSON(t, input, `{"candidates":[{"content":{"parts":[{"text":"plain"}]},"finishReason":"STOP"}]}`)
	if _, exists := out["output"].([]any)[0].(map[string]any)["encrypted_content"]; exists {
		t.Fatal("encryption include not respected")
	}
	if _, err := responsesDecodeRequest([]byte(`{"model":"gemini-test","input":[{"type":"reasoning","id":"rs_other","summary":[],"encrypted_content":""}]}`), testKey); err == nil {
		t.Fatal("unsigned reasoning replay accepted")
	}
}
