package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const responsesTestLimit = 8 << 20

func responsesTestInput(t *testing.T, body string) responsesInput {
	t.Helper()
	input, err := responsesDecodeRequest([]byte(body), testKey)
	if err != nil {
		t.Fatal(err)
	}
	return input
}
func responsesTestMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&out); err != nil {
		t.Fatalf("decode: %v: %s", err, raw)
	}
	return out
}
func responsesTestJSON(t *testing.T, input responsesInput, native string) map[string]any {
	t.Helper()
	out, err := responsesConvertJSON([]byte(native), input, testKey, "resp_test", 123, responsesTestLimit)
	if err != nil {
		t.Fatal(err)
	}
	return responsesTestMap(t, out)
}
func responsesTestEvents(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, event := range strings.Split(stream, "\n\n") {
		if event == "" {
			continue
		}
		lines := strings.Split(event, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
			t.Fatalf("invalid Responses SSE: %q", event)
		}
		frame := responsesTestMap(t, []byte(strings.TrimPrefix(lines[1], "data: ")))
		if frame["type"] != strings.TrimPrefix(lines[0], "event: ") {
			t.Fatal("SSE event/type mismatch")
		}
		if frame["sequence_number"] != json.Number(string(chatRaw(len(out)))) {
			t.Fatal("non-monotonic sequence_number")
		}
		out = append(out, frame)
	}
	return out
}
func responsesTestSSE(events ...string) string {
	return "data: " + strings.Join(events, "\n\ndata: ") + "\n\n"
}
func responsesTestCall(p *proxy, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testKey)
	w := httptest.NewRecorder()
	p.responsesRoute(w, r)
	return w
}

func TestResponsesRequestRolesInstructionsAndLargeIntegers(t *testing.T) {
	instructions := "  You are Pi.\nKeep this exact.\n"
	project := "\n# AGENTS.md\nDo not rewrite me.  "
	body := map[string]any{"model": "gemini-test", "instructions": instructions, "input": []any{map[string]any{"role": "system", "content": project}, map[string]any{"type": "message", "role": "developer", "content": []any{map[string]any{"type": "input_text", "text": "developer text"}}}, map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "hello"}}}, map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "world", "annotations": []any{}, "logprobs": []any{}}}}, map[string]any{"role": "user", "content": "again"}}, "store": false, "background": false, "truncation": "disabled", "reasoning": map[string]any{"effort": "high", "summary": "auto"}, "max_output_tokens": json.Number("9007199254740993"), "temperature": 0.5, "top_p": 0.9, "include": []string{"reasoning.encrypted_content"}, "metadata": map[string]string{"trace": "kept"}, "text": map[string]any{"format": map[string]any{"type": "text"}}}
	input := responsesTestInput(t, string(chatRaw(body)))
	native := responsesTestMap(t, input.Gemini)
	system := native["systemInstruction"].(map[string]any)["parts"].([]any)
	if system[0].(map[string]any)["text"] != instructions || system[1].(map[string]any)["text"] != project || system[2].(map[string]any)["text"] != "developer text" {
		t.Fatal("instructions rewritten or reordered")
	}
	contents := native["contents"].([]any)
	if len(contents) != 3 || contents[1].(map[string]any)["role"] != "model" {
		t.Fatal("role conversion changed history")
	}
	config := native["generationConfig"].(map[string]any)
	if config["maxOutputTokens"] != json.Number("9007199254740993") {
		t.Fatal("integer rounded")
	}
	if config["thinkingConfig"].(map[string]any)["thinkingLevel"] != "HIGH" || !input.Encrypted || !input.Summary {
		t.Fatal("reasoning missing")
	}
	if strings.Contains(string(input.Gemini), "Antigravity Agent") {
		t.Fatal("identity injected")
	}
}

func TestResponsesSDKToolsFormatsMedia(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":[{"role":"user","content":[{"type":"input_text","text":"look"},{"type":"input_image","image_url":"data:image/png;base64,aGk=","detail":"auto"},{"type":"input_video","video_url":"data:video/mp4;base64,aGk="},{"type":"input_audio","input_audio":{"data":"aGk=","format":"wav"}}]}],"tools":[{"type":"function","name":"read.file","description":"exact.name","strict":null,"parameters":{"type":"object","properties":{"n":{"enum":[9007199254740993],"oneOf":[{"type":"integer"}]}}}}],"tool_choice":{"type":"function","name":"read.file"},"parallel_tool_calls":true,"text":{"format":{"type":"json_schema","name":"result","schema":{"type":"object","properties":{"n":{"const":9007199254740993}}},"strict":false}}}`)
	raw := string(input.Gemini)
	for _, want := range []string{"image/png", "video/mp4", "audio/wav", "parametersJsonSchema", "9007199254740993", "oneOf", "read.file", "allowedFunctionNames", "responseJsonSchema"} {
		if !strings.Contains(raw, want) {
			t.Errorf("lost %s", want)
		}
	}
	for _, choice := range []string{`"auto"`, `"none"`, `"required"`} {
		responsesTestInput(t, `{"model":"gemini-test","input":"hi","tools":[{"type":"function","name":"f"}],"tool_choice":`+choice+`}`)
	}
	responsesTestInput(t, `{"model":"gemini-test","input":"hi","stream":true,"stream_options":{"include_obfuscation":false},"reasoning":{"effort":null,"summary":null},"instructions":null,"text":{"format":{"type":"json_object"}}}`)
}

func TestResponsesRejectsUnsupportedAndMalformed(t *testing.T) {
	base := `"model":"gemini-test","input":"hi"`
	for _, field := range []string{`"store":true`, `"store":null`, `"previous_response_id":null`, `"previous_response_id":"resp_x"`, `"conversation":"x"`, `"background":true`, `"truncation":"auto"`, `"service_tier":"priority"`, `"prompt_cache_key":"x"`, `"max_output_tokens":0`, `"max_output_tokens":1.5`, `"temperature":"auto"`, `"top_p":2`, `"parallel_tool_calls":false`, `"stream":"yes"`, `"stream_options":{}`, `"stream":true,"stream_options":{"include_obfuscation":true}`, `"reasoning":{"effort":"none"}`, `"reasoning":{"summary":"detailed"}`, `"reasoning":{"generate_summary":"auto"}`, `"tools":[{"type":"web_search_preview"}]`, `"tools":[{"type":"function","name":"f","strict":true}]`, `"tool_choice":"required"`, `"include":["message.output_text.logprobs"]`, `"include":["reasoning.encrypted_content","reasoning.encrypted_content"]`, `"text":{"verbosity":"low"}`, `"text":{"format":{"type":"text","schema":{}}}`, `"metadata":{"x":null}`, `"metadata":{"x":1}`, `"seed":1`, `"max_tool_calls":2`, `"instructions":42`, `"model input":"ignored?"`} {
		if _, err := responsesDecodeRequest([]byte(`{`+base+`,`+field+`}`), testKey); err == nil {
			t.Errorf("unsupported semantics accepted: %s", field)
		}
	}
	for _, body := range []string{`null`, `[]`, `{`, `{} {}`, `{"model":"gemini-test","input":"hi"} null`, `{"model":"gemini-test","model":"gemini-other","input":"hi"}`, `{"model":"gemini-test","input":[{"role":"user","role":"assistant","content":"hi"}]}`, `{"model":"gemini-test","input":[]}`, `{"model":"gemini-test","input":null}`, `{"model":"gemini-test","input":[{"type":null,"role":"user","content":"hi"}]}`, `{"model":"agy/gemini-test","input":"hi"}`, `{"model":"gemini-test","input":[{"role":"user","content":"hi"},{"role":"developer","content":"late"}]}`, `{"model":"gemini-test","input":[{"type":"function_call","call_id":"x","name":"f","arguments":"{}"}]}`, `{"model":"gemini-test","input":[{"type":"function_call_output","call_id":"orphan","output":"ok"}]}`, `{"model":"gemini-test","input":[{"type":"reasoning","id":"rs_x","summary":[]}]}`, `{"model":"gemini-test","input":[{"type":"item_reference","id":"msg_stored"}]}`} {
		if _, err := responsesDecodeRequest([]byte(body), testKey); err == nil {
			t.Errorf("malformed/unsupported input accepted: %s", body)
		}
	}
	for _, content := range []string{`{"type":"input_image","image_url":"https://private.invalid/x"}`, `{"type":"input_image","image_url":"data:image/png;base64,???"}`, `{"type":"input_image","image_url":"data:image/png;base64,aGk=","detail":"high"}`, `{"type":"input_file","file_id":"f"}`, `{"type":"input_audio","input_audio":{"format":"flac","data":"aGk="}}`, `{"type":"input_text","text":null}`, `{"type":"input_text","text":"x","unknown":true}`, `{"type":"input_audio","input_audio":{"format":"wav","data":"aGk="},"text":"silently ignored?"}`} {
		body := `{"model":"gemini-test","input":[{"role":"user","content":[` + content + `]}]}`
		if _, err := responsesDecodeRequest([]byte(body), testKey); err == nil {
			t.Errorf("bad content accepted: %s", content)
		}
	}
	deep := `{"model":"gemini-test","input":` + strings.Repeat("[", 140) + `0` + strings.Repeat("]", 140) + `}`
	if _, err := responsesDecodeRequest([]byte(deep), testKey); err == nil {
		t.Fatal("nesting unbounded")
	}
}

const responsesTestParts = `[{"thought":true,"text":"think ","thoughtSignature":"thought-sig","futureCarrier":{"n":9007199254740993}},{"text":"before  "},{"functionCall":{"name":"read","id":"native-id","args":{"n":9007199254740993,"value":"a"},"future":"kept"},"thoughtSignature":"call-sig"},{"thoughtSignature":"signature-only","opaqueCarrier":{"future":true}},{"functionCall":{"name":"other","args":{}}},{"text":" after\n"}]`

func responsesTestReplayFixture(t *testing.T) (responsesInput, map[string]any, []any) {
	t.Helper()
	input := responsesTestInput(t, `{"model":"gemini-test","instructions":"Keep Pi and project rules.  ","input":[{"role":"user","content":"use tools"}],"include":["reasoning.encrypted_content"],"reasoning":{"summary":"auto"},"store":false}`)
	output := responsesTestJSON(t, input, `{"response":{"candidates":[{"index":0,"content":{"role":"model","parts":`+responsesTestParts+`},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":4,"thoughtsTokenCount":3,"cachedContentTokenCount":8,"totalTokenCount":99}},"traceId":"private-not-a-model-part"}`)
	history := []any{map[string]any{"role": "user", "content": "use tools"}}
	history = append(history, output["output"].([]any)...)
	return input, output, history
}
func responsesTestReplayRequest(history []any) map[string]any {
	return map[string]any{"model": "gemini-test", "instructions": "Keep Pi and project rules.  ", "input": history, "store": false, "include": []string{"reasoning.encrypted_content"}}
}
func responsesTestResults(output map[string]any) []any {
	var results []any
	for _, value := range output["output"].([]any) {
		item := value.(map[string]any)
		if item["type"] == "function_call" {
			results = append(results, map[string]any{"type": "function_call_output", "call_id": item["call_id"], "output": "ok"})
		}
	}
	// Parallel results may arrive in a different order from the calls.
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}
	return results
}

func TestResponsesJSONEncryptedNativeReplayUsage(t *testing.T) {
	_, output, history := responsesTestReplayFixture(t)
	if output["object"] != "response" || output["id"] != "resp_test" || output["status"] != "completed" || output["store"] != false {
		t.Fatal("bad response lifecycle")
	}
	items := output["output"].([]any)
	if len(items) != 5 || items[0].(map[string]any)["type"] != "reasoning" || items[1].(map[string]any)["type"] != "message" || items[2].(map[string]any)["call_id"] != "native-id" || items[4].(map[string]any)["type"] != "message" {
		t.Fatal("output order/IDs changed")
	}
	reasoning := items[0].(map[string]any)
	blob := reasoning["encrypted_content"].(string)
	if !strings.HasPrefix(blob, responsesBlobPrefix) || strings.Contains(blob, "thought-sig") {
		t.Fatal("replay is not opaque encrypted data")
	}
	turn, err := responsesDecrypt(testKey, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !sameChatJSON(chatRaw(turn.Parts), []byte(responsesTestParts)) || turn.Summary != "think " {
		t.Fatal("native carriers lost")
	}
	if strings.Contains(string(chatRaw(turn)), "traceId") || strings.Contains(string(chatRaw(turn)), "access_token") {
		t.Fatal("non-model account/envelope data in blob")
	}
	// Encryption has a random nonce, even for the same turn.
	second, err := responsesEncrypt(testKey, turn)
	if err != nil || second == blob {
		t.Fatal("reused encryption nonce")
	}
	usage := output["usage"].(map[string]any)
	if usage["input_tokens"] != json.Number("20") || usage["output_tokens"] != json.Number("7") || usage["total_tokens"] != json.Number("99") || usage["output_tokens_details"].(map[string]any)["reasoning_tokens"] != json.Number("3") || usage["input_tokens_details"].(map[string]any)["cached_tokens"] != json.Number("8") {
		t.Fatal("wrong Responses usage")
	}
	history = append(history, responsesTestResults(output)...)
	request := responsesTestReplayRequest(history)
	input, err := responsesDecodeRequest(chatRaw(request), testKey)
	if err != nil {
		t.Fatal(err)
	}
	native := responsesTestMap(t, input.Gemini)
	contents := native["contents"].([]any)
	if len(contents) != 3 || !sameChatJSON(chatRaw(contents[1].(map[string]any)["parts"]), []byte(responsesTestParts)) {
		t.Fatal("full native model turn not reconstructed in original order")
	}
	results := contents[2].(map[string]any)["parts"].([]any)
	if len(results) != 2 || results[0].(map[string]any)["functionResponse"].(map[string]any)["name"] != "other" || results[1].(map[string]any)["functionResponse"].(map[string]any)["id"] != "native-id" {
		t.Fatal("tool result matching or native IDs lost")
	}
	if !strings.Contains(string(input.Gemini), "9007199254740993") {
		t.Fatal("large int rounded on encrypted replay")
	}
	// A real second response can itself be replayed after the first complete turn.
	secondOutput := responsesTestJSON(t, input, `{"candidates":[{"content":{"parts":[{"text":"done","thoughtSignature":"second-turn-signature"}]},"finishReason":"STOP"}]}`)
	history = append(history, secondOutput["output"].([]any)...)
	history = append(history, map[string]any{"role": "user", "content": "next"})
	if _, err := responsesDecodeRequest(chatRaw(responsesTestReplayRequest(history)), testKey); err != nil {
		t.Fatalf("two signed turns failed: %v", err)
	}
}

func TestResponsesReplayRejectsTamperWrongKeyModelContextAndIncompleteOutput(t *testing.T) {
	cases := map[string]func(map[string]any, []any){
		"model":           func(req map[string]any, _ []any) { req["model"] = "gemini-other" },
		"instructions":    func(req map[string]any, _ []any) { req["instructions"] = "changed" },
		"earlier context": func(_ map[string]any, h []any) { h[0].(map[string]any)["content"] = "changed" },
		"visible whitespace": func(_ map[string]any, h []any) {
			h[2].(map[string]any)["content"].([]any)[0].(map[string]any)["text"] = "before"
		},
		"function arguments": func(_ map[string]any, h []any) {
			h[3].(map[string]any)["arguments"] = `{"n":9007199254740992,"value":"a"}`
		},
		"function name": func(_ map[string]any, h []any) { h[3].(map[string]any)["name"] = "evil" },
		"call id":       func(_ map[string]any, h []any) { h[3].(map[string]any)["call_id"] = "other" },
		"summary": func(_ map[string]any, h []any) {
			h[1].(map[string]any)["summary"] = []any{map[string]any{"type": "summary_text", "text": "altered"}}
		},
		"blob": func(_ map[string]any, h []any) {
			item := h[1].(map[string]any)
			blob := item["encrypted_content"].(string)
			encoded, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(blob, responsesBlobPrefix))
			encoded[len(encoded)-1] ^= 1
			item["encrypted_content"] = responsesBlobPrefix + base64.RawURLEncoding.EncodeToString(encoded)
		},
		"foreign encryption": func(_ map[string]any, h []any) { h[1].(map[string]any)["encrypted_content"] = "gAAAA-openai-opaque" },
		"reordered items":    func(_ map[string]any, h []any) { h[2], h[3] = h[3], h[2] },
		"omitted item":       func(req map[string]any, h []any) { req["input"] = append(h[:2], h[3:]...) },
		"omitted reasoning":  func(req map[string]any, h []any) { req["input"] = append(h[:1], h[2:]...) },
		"omitted results":    func(req map[string]any, h []any) { req["input"] = h[:6] },
		"orphan result":      func(_ map[string]any, h []any) { h[len(h)-1].(map[string]any)["call_id"] = "not-pending" },
		"duplicate result":   func(req map[string]any, h []any) { req["input"] = append(h, h[len(h)-1]) },
		"interrupted results": func(req map[string]any, h []any) {
			req["input"] = append(append(h[:6:6], map[string]any{"role": "user", "content": "not a result"}), h[6:]...)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, output, h := responsesTestReplayFixture(t)
			h = append(h, responsesTestResults(output)...)
			req := responsesTestReplayRequest(h)
			mutate(req, h)
			if _, err := responsesDecodeRequest(chatRaw(req), testKey); err == nil {
				t.Fatal("invalid replay accepted")
			}
		})
	}
	_, output, h := responsesTestReplayFixture(t)
	h = append(h, responsesTestResults(output)...)
	if _, err := responsesDecodeRequest(chatRaw(responsesTestReplayRequest(h)), "wrong-key"); err == nil {
		t.Fatal("wrong key accepted")
	}
	// SDK serializers may omit status/item IDs and reformat valid argument JSON.
	for _, value := range h[1:6] {
		item := value.(map[string]any)
		delete(item, "id")
		delete(item, "status")
		if item["type"] == "function_call" && item["name"] == "read" {
			item["arguments"] = `{ "value":"a", "n":9007199254740993 }`
		}
	}
	if _, err := responsesDecodeRequest(chatRaw(responsesTestReplayRequest(h)), testKey); err != nil {
		t.Fatalf("benign SDK normalization rejected: %v", err)
	}
}

func TestResponsesStreamLifecycleDeltasAndRoundTrip(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi","stream":true,"store":false,"include":["reasoning.encrypted_content"],"reasoning":{"effort":"high","summary":"auto"}}`)
	native := responsesTestSSE(`{"response":{"candidates":[{"content":{"parts":[{"thought":true,"text":"think","thoughtSignature":"thought"},{"text":"a"}]}}]}}`, `{"response":{"candidates":[{"content":{"parts":[{"text":"b"},{"functionCall":{"name":"lookup","args":{"n":9007199254740993}},"thoughtSignature":"sig"}]}}]}}`, `{"response":{"candidates":[{"content":{"parts":[{"thoughtSignature":"tail","opaqueCarrier":{"v":1}}]},"finishReason":"STOP"}]}}`, `{"response":{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":3,"cachedContentTokenCount":4}}}`)
	native = "\ufeff: hello\r\n\r\n" + strings.ReplaceAll(native, "\n", "\r\n")
	var out bytes.Buffer
	flushes := 0
	if err := responsesConvertStream(&out, &responsesTestByteReader{value: native}, input, testKey, "resp_stream", 123, responsesTestLimit, func() { flushes++ }); err != nil {
		t.Fatal(err)
	}
	events := responsesTestEvents(t, out.String())
	if flushes != len(events) || events[0]["type"] != "response.created" || events[1]["type"] != "response.in_progress" || events[len(events)-1]["type"] != "response.completed" {
		t.Fatal("bad lifecycle")
	}
	var text, summary, args strings.Builder
	added, done := map[string]int{}, map[string]int{}
	for _, event := range events {
		switch event["type"] {
		case "response.output_text.delta":
			text.WriteString(event["delta"].(string))
		case "response.reasoning_summary_text.delta":
			summary.WriteString(event["delta"].(string))
		case "response.function_call_arguments.delta":
			args.WriteString(event["delta"].(string))
		case "response.output_item.added":
			added[event["item"].(map[string]any)["id"].(string)]++
		case "response.output_item.done":
			done[event["item"].(map[string]any)["id"].(string)]++
		}
	}
	if text.String() != "ab" || summary.String() != "think" || args.String() != `{"n":9007199254740993}` {
		t.Fatal("delta accumulation changed output")
	}
	for id, n := range added {
		if n != 1 || done[id] != 1 {
			t.Fatal("output item lifecycle not unique")
		}
	}
	response := events[len(events)-1]["response"].(map[string]any)
	if response["usage"].(map[string]any)["total_tokens"] != json.Number("15") {
		t.Fatal("trailing native usage lost")
	}
	h := []any{map[string]any{"role": "user", "content": "hi"}}
	h = append(h, response["output"].([]any)...)
	h = append(h, responsesTestResults(response)...)
	next, err := responsesDecodeRequest(chatRaw(map[string]any{"model": "gemini-test", "input": h}), testKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"9007199254740993", "thoughtSignature", "opaqueCarrier", "tail"} {
		if !strings.Contains(string(next.Gemini), want) {
			t.Fatalf("stream replay lost %s", want)
		}
	}
}

type responsesTestByteReader struct{ value string }

func (r *responsesTestByteReader) Read(p []byte) (int, error) {
	if r.value == "" {
		return 0, io.EOF
	}
	p[0], r.value = r.value[0], r.value[1:]
	return 1, nil
}

type responsesTestErrorReader struct{}

func (responsesTestErrorReader) Read([]byte) (int, error) { return 0, errors.New("private credential") }

type responsesTestShortWriter struct{}

func (responsesTestShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestResponsesNeverCompletesFailedOrTruncatedStream(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi","stream":true,"include":["reasoning.encrypted_content"]}`)
	valid := `{"candidates":[{"content":{"parts":[{"text":"hi"}]},"finishReason":"STOP"}]}`
	for name, native := range map[string]string{
		"empty": "", "missing finish": responsesTestSSE(`{"candidates":[{"content":{"parts":[{"text":"partial"}]}}]}`), "missing boundary": "data: " + valid + "\n", "missing line end": "data: " + valid, "trailing comment": responsesTestSSE(valid) + ": trailing\n", "fake done": responsesTestSSE(`{"candidates":[{}]}`, "[DONE]"), "error": responsesTestSSE(`{"error":{"message":"private credential"}}`), "error event": "event: error\n\n", "trailing error": responsesTestSSE(valid, `{"error":{"message":"private credential"}}`), "prompt block": responsesTestSSE(`{"promptFeedback":{"blockReason":"SAFETY"},"response":` + valid + `}`), "multiple candidates": responsesTestSSE(`{"candidates":[{"finishReason":"STOP"},{"finishReason":"STOP"}]}`), "different index": responsesTestSSE(`{"candidates":[{"index":1,"finishReason":"STOP"}]}`), "after finish": responsesTestSSE(valid, valid), "after done": responsesTestSSE(valid, "[DONE]", valid), "unknown finish": responsesTestSSE(`{"candidates":[{"finishReason":"OTHER"}]}`), "output media": responsesTestSSE(`{"candidates":[{"content":{"parts":[{"inlineData":{"data":"aGk="}}]},"finishReason":"STOP"}]}`), "bad usage": responsesTestSSE(valid, `{"usageMetadata":{"promptTokenCount":-1}}`), "malformed JSON": responsesTestSSE(`{"response":`), "duplicate JSON": responsesTestSSE(`{"candidates":[],"candidates":[{"finishReason":"STOP"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := responsesConvertStream(&out, strings.NewReader(native), input, testKey, "resp_fail", 1, responsesTestLimit, nil)
			if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(out.String(), "response.completed") || strings.Contains(out.String(), "response.incomplete") || strings.Contains(out.String(), "private credential") {
				t.Fatalf("failed stream succeeded/leaked: %v", err)
			}
			events := responsesTestEvents(t, out.String())
			if events[len(events)-1]["type"] != "response.failed" {
				t.Fatal("failure lifecycle missing")
			}
		})
	}
	for _, src := range []io.Reader{responsesTestErrorReader{}, io.MultiReader(strings.NewReader(responsesTestSSE(valid)), responsesTestErrorReader{})} {
		var out bytes.Buffer
		if err := responsesConvertStream(&out, src, input, testKey, "resp_fail", 1, responsesTestLimit, nil); err == nil || strings.Contains(out.String(), "response.completed") {
			t.Fatal("read failure completed")
		}
	}
	if err := responsesConvertStream(responsesTestShortWriter{}, strings.NewReader(responsesTestSSE(valid)), input, testKey, "resp_fail", 1, responsesTestLimit, nil); err == nil {
		t.Fatal("short write accepted")
	}
}

func TestResponsesFinishAndBounds(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi"}`)
	for _, finish := range []string{"MAX_TOKENS", "SAFETY", "RECITATION"} {
		out := responsesTestJSON(t, input, `{"candidates":[{"content":{"parts":[{"text":"partial"}]},"finishReason":"`+finish+`"}]}`)
		if out["status"] != "incomplete" {
			t.Fatal("incomplete native finish became completed")
		}
	}
	for _, bad := range []string{`null`, `[]`, `{}`, `{"response":null}`, `{"candidates":[{}]}`, `{"candidates":[{"content":{"parts":[{"text":null}]},"finishReason":"STOP"}]}`, `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f","args":{"n":1,"n":2}}}]},"finishReason":"STOP"}]}`, `{"candidates":[{"content":{"parts":[{"thoughtSignature":null}]},"finishReason":"STOP"}]}`, `{"candidates":[{"content":{"parts":[{"futureOutput":{}}]},"finishReason":"STOP"}]}`, `{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9223372036854775807,"thoughtsTokenCount":1}}`} {
		if _, err := responsesConvertJSON([]byte(bad), input, testKey, "resp_x", 1, responsesTestLimit); err == nil {
			t.Errorf("bad native JSON accepted: %s", bad)
		}
	}
	valid := `{"candidates":[{"content":{"parts":[{"text":"` + strings.Repeat("x", 4096) + `"}]},"finishReason":"STOP"}]}`
	if _, err := responsesConvertJSON([]byte(valid), input, testKey, "resp_x", 1, 512); err == nil {
		t.Fatal("JSON input bound ignored")
	}
	var out bytes.Buffer
	if err := responsesConvertStream(&out, strings.NewReader(responsesTestSSE(valid)), input, testKey, "resp_x", 1, 2048, nil); err == nil || strings.Contains(out.String(), "response.completed") {
		t.Fatal("stream bound ignored")
	}
	state := responsesNewState(input, testKey, "resp_x", 1, 100, nil)
	_ = state.start()
	state.nativeBytes = 99
	frame, _ := chatResponseDecodeFrame([]byte(`{"candidates":[{"content":{"parts":[{"text":"x"}]}}]}`))
	if err := state.apply(frame); err == nil {
		t.Fatal("aggregate native state bound ignored")
	}
	for _, count := range []string{"parts", "tools"} {
		state = responsesNewState(input, testKey, "resp_x", 1, responsesTestLimit, nil)
		_ = state.start()
		if count == "parts" {
			state.parts = make([]json.RawMessage, chatResponseMaxParts)
		} else {
			state.tools = chatResponseMaxTools
		}
		part := `{"text":"x"}`
		if count == "tools" {
			part = `{"functionCall":{"name":"f","args":{}}}`
		}
		frame, _ = chatResponseDecodeFrame([]byte(`{"candidates":[{"content":{"parts":[` + part + `]}}]}`))
		if err := state.apply(frame); err == nil {
			t.Fatalf("%s bound ignored", count)
		}
	}
}

func TestResponsesRouteAuthErrorsNoRetryAndNoRedirect(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "23")
		w.Header().Set("Location", "https://evil.invalid/private")
		w.Header().Set("Set-Cookie", "private")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}`)
	}, fixedCredentials{credential{AccessToken: "google-private", Project: "project-private"}})
	for _, tc := range []struct {
		method, path, auth, goog, body string
		status                         int
	}{
		{"POST", "/v1/responses", "", "", `{}`, 401}, {"POST", "/v1/responses", "Basic x", "", `{}`, 401}, {"POST", "/v1/responses", "Bearer " + testKey, "conflicting", `{}`, 401}, {"POST", "/v1/responses?key=x", "Bearer " + testKey, "", `{}`, 400}, {"GET", "/v1/responses/resp_x", "Bearer " + testKey, "", "", 404}, {"POST", "/v1/responses/resp_x/cancel", "Bearer " + testKey, "", `{}`, 404}, {"POST", "/v1/responses", "Bearer " + testKey, "", `{"model":"gemini-test","input":"hi","store":true}`, 400},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", tc.auth)
		r.Header.Set("X-Goog-Api-Key", tc.goog)
		w := httptest.NewRecorder()
		p.responsesRoute(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: got %d want %d: %s", tc.path, w.Code, tc.status, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached credentials/upstream")
	}
	w := responsesTestCall(p, `{"model":"gemini-test","input":"hi","stream":true}`)
	if w.Code != 429 || calls.Load() != 1 || w.Header().Get("Retry-After") != "23" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" || !strings.Contains(w.Body.String(), "RESOURCE_EXHAUSTED") {
		t.Fatal("native error hidden, retried or leaked headers")
	}
	// A generation redirect is returned as an error envelope, never followed.
	p = testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "https://evil.invalid/private")
		w.WriteHeader(307)
	}, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
	w = responsesTestCall(p, `{"model":"gemini-test","input":"hi"}`)
	if w.Code != 307 || calls.Load() != 2 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "upstream_error") {
		t.Fatal("redirect followed or exposed")
	}
}

func TestResponsesRouteNativeEnvelopeAndJSON(t *testing.T) {
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1internal:generateContent" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer google-private" || r.Header.Get("X-Goog-Api-Key") != "" {
			t.Error("wrong upstream route or credentials")
		}
		var envelope struct {
			Model, Project string
			Request        struct {
				Session string                                  `json:"sessionId"`
				System  struct{ Parts []struct{ Text string } } `json:"systemInstruction"`
			}
		}
		if json.NewDecoder(r.Body).Decode(&envelope) != nil || envelope.Project != "private-project" || envelope.Model != "gemini-test" || envelope.Request.Session != "stable-session" || envelope.Request.System.Parts[0].Text != "  Pi identity\nproject rules  " {
			t.Error("envelope/system modified")
		}
		_, _ = io.WriteString(w, `{"response":{"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}]}}`)
	}, fixedCredentials{credential{AccessToken: "google-private", Project: "private-project"}})
	r := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"model":"gemini-test","instructions":"  Pi identity\nproject rules  ","input":"hi","include":["reasoning.encrypted_content"]}`))
	r.Header.Set("X-Goog-Api-Key", testKey)
	r.Header.Set("X-Session-Id", "stable-session")
	w := httptest.NewRecorder()
	p.responsesRoute(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "google-private") || strings.Contains(w.Body.String(), "private-project") {
		t.Fatalf("wrong response or leaked credentials: HTTP %d", w.Code)
	}
	out := responsesTestMap(t, w.Body.Bytes())
	if out["status"] != "completed" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("bad JSON response")
	}
}

func TestResponsesStreamIsIncrementalAndCancellationPropagates(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "truncated"}[truncated], func(t *testing.T) {
			canceled := make(chan struct{})
			release := make(chan struct{})
			p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1internal:streamGenerateContent" || r.URL.RawQuery != "alt=sse" {
					t.Error("wrong upstream SSE route")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, responsesTestSSE(`{"candidates":[{"content":{"parts":[{"text":"incremental"}]}}]}`))
				w.(http.Flusher).Flush()
				close(release)
				if !truncated {
					<-r.Context().Done()
					close(canceled)
				}
			}, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
			server := httptest.NewServer(http.HandlerFunc(p.responsesRoute))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/responses", strings.NewReader(`{"model":"gemini-test","input":"hi","stream":true,"include":["reasoning.encrypted_content"]}`))
			r.Header.Set("Authorization", "Bearer "+testKey)
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			<-release
			if truncated {
				data, err := io.ReadAll(response.Body)
				if err == nil || strings.Contains(string(data), "response.completed") {
					t.Fatal("truncated stream completed")
				}
			} else {
				// Read through the actual text delta while upstream is deliberately blocked.
				var received strings.Builder
				byteBuf := make([]byte, 1)
				for !strings.Contains(received.String(), `"delta":"incremental"`) {
					n, err := response.Body.Read(byteBuf)
					if err != nil {
						t.Fatal(err)
					}
					received.Write(byteBuf[:n])
				}
				cancel()
				select {
				case <-canceled:
				case <-time.After(3 * time.Second):
					t.Fatal("cancellation did not reach upstream")
				}
			}
		})
	}
}
