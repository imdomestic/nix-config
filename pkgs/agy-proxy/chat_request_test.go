package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeInputFixture(t *testing.T, request string) map[string]any {
	t.Helper()
	input, err := decodeChatRequest([]byte(request))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if json.Unmarshal(input.Gemini, &body) != nil {
		t.Fatal("invalid generated Gemini JSON")
	}
	return body
}

func TestChatInputTextAndSampling(t *testing.T) {
	body := decodeInputFixture(t, `{"model":"gemini-test","messages":[{"role":"system","content":"Keep my real identity."},{"role":"developer","content":[{"type":"text","text":"Keep tools safe."}]},{"role":"user","content":"hello"},{"role":"assistant","content":"world"},{"role":"user","content":"again"}],"stream":true,"stream_options":{"include_usage":true},"max_tokens":8192,"max_completion_tokens":8192,"temperature":0.5,"top_p":0.9,"reasoning_effort":"high","seed":42,"stop":["END"],"store":false,"n":2}`)
	system := body["systemInstruction"].(map[string]any)
	if system["role"] != "user" || !strings.Contains(string(chatRaw(system)), "Keep my real identity.") || strings.Contains(string(chatRaw(body)), "Antigravity Agent") {
		t.Fatal("system prompt was rewritten")
	}
	contents := body["contents"].([]any)
	if len(contents) != 3 || contents[1].(map[string]any)["role"] != "model" {
		t.Fatal("message roles or order changed")
	}
	config := body["generationConfig"].(map[string]any)
	if config["maxOutputTokens"] != float64(8192) || config["candidateCount"] != float64(2) || config["thinkingConfig"].(map[string]any)["thinkingLevel"] != "HIGH" {
		t.Fatal("generation settings changed")
	}
}

func TestChatInputSchemaAndToolChoice(t *testing.T) {
	base := map[string]any{"model": "gemini-test", "messages": []any{map[string]any{"role": "user", "content": "hi"}}, "tools": []any{map[string]any{"type": "function", "function": map[string]any{"name": "exact.name", "strict": false, "parameters": map[string]any{"type": "object", "properties": map[string]any{"x": map[string]any{"enum": []string{"a", "b"}, "oneOf": []any{map[string]any{"type": "string"}}, "$ref": "#/definitions/native"}}, "required": []string{"x"}}}}}, "response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "format", "schema": map[string]any{"type": "object", "properties": map[string]any{}}, "strict": false}}}
	for _, choice := range []any{"auto", "none", "required", map[string]any{"type": "function", "function": map[string]any{"name": "exact.name"}}} {
		base["tool_choice"] = choice
		body := decodeInputFixture(t, string(chatRaw(base)))
		data := string(chatRaw(body))
		for _, field := range []string{"parametersJsonSchema", "enum", "oneOf", "$ref", "exact.name", "responseJsonSchema"} {
			if !strings.Contains(data, field) {
				t.Errorf("schema field %s lost", field)
			}
		}
		if body["toolConfig"] == nil {
			t.Fatal("tool_choice not mapped")
		}
	}
}

func TestChatInputInlineMediaAndNoURLFetch(t *testing.T) {
	body := decodeInputFixture(t, `{"model":"gemini-test","messages":[{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,aGk="}},{"type":"video_url","video_url":{"url":"data:video/mp4;base64,aGk="}},{"type":"input_audio","input_audio":{"data":"aGk=","format":"wav"}}]}]}`)
	parts := body["contents"].([]any)[0].(map[string]any)["parts"].([]any)
	if len(parts) != 4 || parts[1].(map[string]any)["inlineData"].(map[string]any)["mimeType"] != "image/png" {
		t.Fatal("media mapping wrong")
	}
	for _, part := range []string{`{"type":"image_url","image_url":{"url":"https://private.invalid/picture"}}`, `{"type":"image_url","image_url":{"url":"data:image/png;base64,bad?"}}`, `{"type":"image_url","image_url":{"url":"data:image/png;base64,aGk=","detail":"high"}}`, `{"type":"input_audio","input_audio":{"data":"aGk=","format":"flac"}}`, `{"type":"file","file":{"data":"anything"}}`} {
		request := `{"model":"gemini-test","messages":[{"role":"user","content":[` + part + `]}]}`
		if _, err := decodeChatRequest([]byte(request)); err == nil {
			t.Errorf("unsupported/remote media accepted: %s", part)
		}
	}
}

func TestChatInputExactNativeReplayAndParallelResults(t *testing.T) {
	parts := []json.RawMessage{json.RawMessage(`{"text":"thinking","thought":true,"thoughtSignature":"thought-native-signature","nativeFuture":{"keep":true}}`), json.RawMessage(`{"text":"Checking"}`), json.RawMessage(`{"functionCall":{"name":"probe","args":{"value":"ok"},"id":"native-one"},"thoughtSignature":"call-signature"}`), json.RawMessage(`{"functionCall":{"name":"other","args":{}},"thoughtSignature":"second-signature"}`)}
	carrier := map[string]any{"agy": chatReplay{Model: "gemini-test", Parts: parts}}
	calls := []any{map[string]any{"id": "chat-one", "type": "function", "function": map[string]any{"name": "probe", "arguments": `{"value":"ok"}`}, "extra_content": carrier}, map[string]any{"id": "chat-two", "type": "function", "function": map[string]any{"name": "other", "arguments": "{}"}, "extra_content": carrier}}
	for _, messageCarrier := range []bool{false, true} {
		assistant := map[string]any{"role": "assistant", "content": "Checking", "reasoning_content": "thinking", "tool_calls": calls}
		if messageCarrier {
			assistant["extra_content"] = carrier
		}
		request := map[string]any{"model": "gemini-test", "messages": []any{map[string]any{"role": "user", "content": "Use tools"}, assistant, map[string]any{"role": "tool", "tool_call_id": "chat-two", "content": "two"}, map[string]any{"role": "tool", "tool_call_id": "chat-one", "content": "one"}}}
		body := decodeInputFixture(t, string(chatRaw(request)))
		contents := body["contents"].([]any)
		got := contents[1].(map[string]any)["parts"]
		if !sameChatJSON(chatRaw(got), chatRaw(parts)) {
			t.Fatal("native thought/call/signature parts were reconstructed")
		}
		responses := contents[2].(map[string]any)["parts"].([]any)
		if len(contents) != 3 || len(responses) != 2 {
			t.Fatal("adjacent parallel tool results were not grouped")
		}
		first := responses[0].(map[string]any)["functionResponse"].(map[string]any)
		second := responses[1].(map[string]any)["functionResponse"].(map[string]any)
		if first["name"] != "other" || second["name"] != "probe" || second["id"] != "native-one" {
			t.Fatal("tool result order/name/native ID changed")
		}
		assistant["content"] = "tampered"
		if _, err := decodeChatRequest(chatRaw(request)); err == nil {
			t.Fatal("altered replay content silently accepted")
		}
		assistant["content"] = "Checking"
		carrier["agy"] = chatReplay{Model: "gemini-other", Parts: parts}
		if _, err := decodeChatRequest(chatRaw(request)); err == nil {
			t.Fatal("cross-model signature replay accepted")
		}
		carrier["agy"] = chatReplay{Model: "gemini-test", Parts: parts}
	}
}

func TestChatInputSignatureIsNeverInvented(t *testing.T) {
	request := `{"model":"gemini-test","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"probe","arguments":"{}"},"extra_content":{"google":{"thought_signature":"real-sig"}}}]},{"role":"tool","tool_call_id":"c1","content":"ok"}]}`
	body := decodeInputFixture(t, request)
	data := string(chatRaw(body))
	if !strings.Contains(data, `"thoughtSignature":"real-sig"`) || strings.Contains(data, "skip_thought_signature") {
		t.Fatal("signature modified or bypass invented")
	}
}

func TestChatInputRejectsAmbiguousAndUnsupportedSemantics(t *testing.T) {
	base := `"model":"gemini-test","messages":[{"role":"user","content":"hello"}]`
	for _, field := range []string{`"logprobs":true`, `"functions":[]`, `"frequency_penalty":1`, `"parallel_tool_calls":false`, `"store":true`, `"reasoning_effort":"none"`, `"n":0`, `"temperature":3`, `"top_p":0`, `"max_tokens":0`, `"max_tokens":1,"max_completion_tokens":2`, `"stop":[""]`, `"stream_options":{"include_usage":true}`, `"response_format":{"type":"unknown"}`, `"tool_choice":"required"`} {
		if _, err := decodeChatRequest([]byte(`{` + base + `,` + field + `}`)); err == nil {
			t.Errorf("unsupported field accepted: %s", field)
		}
	}
	for _, request := range []string{`null`, `[]`, `{"model":"agy/gemini-test","messages":[{"role":"user","content":"hi"}]}`, `{"model":"gemini-test","messages":[]}`, `{"model":"gemini-test","messages":[{"role":"user","content":"hi","function_call":{}}]}`, `{"model":"gemini-test","messages":[{"role":"user","content":"hi"},{"role":"system","content":"late"}]}`, `{"model":"gemini-test","messages":[{"role":"tool","tool_call_id":"missing","content":"orphan"}]}`, `{"model":"gemini-test","messages":[{"role":"assistant","content":null}]}`, `{"model":"gemini-test","messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"probe","arguments":"{}"}}]},{"role":"user","content":"not a tool result"}]}`} {
		if _, err := decodeChatRequest([]byte(request)); err == nil {
			t.Errorf("ambiguous history accepted: %s", request)
		}
	}
}
