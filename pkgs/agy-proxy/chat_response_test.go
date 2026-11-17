package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func chatTestDecode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode response: %v: %s", err, data)
	}
	return result
}

func chatTestChoices(value map[string]any) []any { return value["choices"].([]any) }
func chatTestMap(value any) map[string]any       { return value.(map[string]any) }

func chatTestFrames(t *testing.T, text string) []map[string]any {
	t.Helper()
	var frames []map[string]any
	for _, event := range strings.Split(text, "\n\n") {
		if event == "" || event == "data: [DONE]" {
			continue
		}
		if !strings.HasPrefix(event, "data: ") {
			t.Fatalf("invalid output event: %q", event)
		}
		frames = append(frames, chatTestDecode(t, []byte(strings.TrimPrefix(event, "data: "))))
	}
	return frames
}

func chatTestSSE(events ...string) string {
	return "data: " + strings.Join(events, "\n\ndata: ") + "\n\n"
}

func TestChatResponseJSONReplayAndUsage(t *testing.T) {
	parts := `[{"text":"before","thoughtSignature":"text-sig"},{"thought":true,"text":"reasoning","thoughtSignature":"thought-sig"},{"thought":true,"thoughtSignature":"only-sig"},{"thoughtSignature":"native-sig","opaqueCarrier":{"future":true},"functionCall":{"id":"native-call","name":"tool.with.dots","args": { "x": 1, "s":"a\\b" },"future":"keep"}},{"functionCall":{"name":"second","args":{}}},{"text":"after"}]`
	input := `{"response":{"candidates":[{"index":7,"content":{"role":"model","parts":` + parts + `},"finishReason":"STOP"},{"index":2,"content":{"parts":[{"text":"other"}]},"finishReason":"MAX_TOKENS"}],"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":4,"thoughtsTokenCount":3,"cachedContentTokenCount":8,"totalTokenCount":99}},"traceId":"private"}`
	data, err := convertChatJSON([]byte(input), "gemini-test", "chatcmpl-test", 123)
	if err != nil {
		t.Fatal(err)
	}
	out := chatTestDecode(t, data)
	if out["object"] != "chat.completion" || out["id"] != "chatcmpl-test" || out["created"] != float64(123) || out["model"] != "gemini-test" {
		t.Fatal("incorrect response identity")
	}
	choices := chatTestChoices(out)
	first := chatTestMap(choices[0])
	if first["index"] != float64(7) || first["finish_reason"] != "tool_calls" || chatTestMap(choices[1])["index"] != float64(2) || chatTestMap(choices[1])["finish_reason"] != "length" {
		t.Fatal("candidate indices or finish reasons lost")
	}
	message := chatTestMap(first["message"])
	if message["content"] != "beforeafter" || message["reasoning_content"] != "reasoning" {
		t.Fatal("text and thoughts were not separated")
	}
	replay := chatTestMap(chatTestMap(message["extra_content"])["agy"])
	if replay["model"] != "gemini-test" {
		t.Fatal("replay model missing")
	}
	var expected any
	_ = json.Unmarshal([]byte(parts), &expected)
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(replay["parts"])
	if !bytes.Equal(got, want) {
		t.Fatalf("native replay changed: %s != %s", got, want)
	}
	tools := message["tool_calls"].([]any)
	for i, value := range tools {
		tool := chatTestMap(value)
		extra := chatTestMap(tool["extra_content"])
		got, _ := json.Marshal(extra["agy"])
		want, _ := json.Marshal(replay)
		if !bytes.Equal(got, want) {
			t.Fatal("tool-only replay fallback differs from message")
		}
		if _, exists := tool["index"]; exists {
			t.Fatal("stream-only tool index in JSON response")
		}
		if i == 0 {
			if tool["id"] != "native-call" || chatTestMap(extra["google"])["thought_signature"] != "native-sig" || chatTestMap(tool["function"])["arguments"] != `{"x":1,"s":"a\\b"}` {
				t.Fatal("native tool id/signature/complete arguments changed")
			}
		} else if !strings.HasPrefix(tool["id"].(string), "call_") || len(tool["id"].(string)) != 41 || extra["google"] != nil {
			t.Fatal("fallback UUID missing or signature fabricated")
		}
	}
	usage := chatTestMap(out["usage"])
	if usage["prompt_tokens"] != float64(20) || usage["completion_tokens"] != float64(7) || usage["total_tokens"] != float64(99) || chatTestMap(usage["completion_tokens_details"])["reasoning_tokens"] != float64(3) || chatTestMap(usage["prompt_tokens_details"])["cached_tokens"] != float64(8) {
		t.Fatalf("incorrect usage: %v", usage)
	}
}

func TestChatResponseStreamDeltasAndTerminalReplay(t *testing.T) {
	events := []string{
		`{"response":{"candidates":[{"index":4,"content":{"parts":[{"text":"a"},{"thought":true,"text":"think"}]}},{"index":8,"content":{"parts":[{"text":"other"}]}}]}}`,
		`{"response":{"candidates":[{"index":4,"content":{"parts":[{"text":"a"},{"functionCall":{"name":"lookup","args":{"n":1}},"thoughtSignature":"real"},{"functionCall":{"name":"lookup","args":{"n":2}}}]}}]}}`,
		`{"response":{"candidates":[{"index":8,"finishReason":"STOP"},{"index":4,"content":{"parts":[{"thoughtSignature":"last"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":3,"cachedContentTokenCount":4}}}`,
	}
	// The first event is multiline JSON, with comments between data fields.
	stream := "\ufeff: comment\r\nid: ignored\r\ndata: {\r\n: middle\r\ndata: " + strings.TrimPrefix(events[0], "{") + "\r\n\r\n" + chatTestSSE(events[1:]...) + ": keepalive\n\n"
	var dst bytes.Buffer
	flushes := 0
	if err := convertChatStream(&dst, &chatTestByteReader{value: stream}, "gemini-test", "chatcmpl-test", 12, true, func() { flushes++ }); err != nil {
		t.Fatal(err)
	}
	if strings.Count(dst.String(), "data: [DONE]\n\n") != 1 || !strings.HasSuffix(dst.String(), "data: [DONE]\n\n") {
		t.Fatal("missing unique terminal DONE")
	}
	frames := chatTestFrames(t, dst.String())
	if flushes != len(frames)+1 {
		t.Fatal("frames were not flushed")
	}
	var text, thought string
	roles := map[float64]int{}
	tools := map[float64]map[string]any{}
	terminals := 0
	for _, frame := range frames {
		if frame["object"] != "chat.completion.chunk" {
			t.Fatal("wrong streaming object")
		}
		for _, choiceValue := range chatTestChoices(frame) {
			choice := chatTestMap(choiceValue)
			index := choice["index"].(float64)
			delta := chatTestMap(choice["delta"])
			if delta["role"] != nil {
				roles[index]++
			}
			if index == 4 {
				if v, ok := delta["content"].(string); ok {
					text += v
				}
				if v, ok := delta["reasoning_content"].(string); ok {
					thought += v
				}
			}
			if choice["finish_reason"] != nil {
				terminals++
				if delta["role"] != nil || delta["content"] != nil || delta["reasoning_content"] != nil {
					t.Fatal("terminal chunk reemits role or text")
				}
				if index == 4 {
					if choice["finish_reason"] != "tool_calls" {
						t.Fatal("missing tool finish")
					}
					agy := chatTestMap(chatTestMap(delta["extra_content"])["agy"])
					if len(agy["parts"].([]any)) != 6 {
						t.Fatal("native delta parts lost or deduplicated")
					}
					for _, item := range delta["tool_calls"].([]any) {
						tool := chatTestMap(item)
						if len(tool) != 2 || tool["id"] != nil || tool["function"] != nil {
							t.Fatal("terminal metadata reemits call")
						}
						extra := chatTestMap(tool["extra_content"])
						got, _ := json.Marshal(extra["agy"])
						want, _ := json.Marshal(agy)
						if !bytes.Equal(got, want) {
							t.Fatal("terminal tool replay differs")
						}
						if tool["index"] == float64(0) && chatTestMap(extra["google"])["thought_signature"] != "real" {
							t.Fatal("lost native signature")
						}
						if tool["index"] == float64(1) && extra["google"] != nil {
							t.Fatal("fabricated native signature")
						}
					}
				}
			} else if items, ok := delta["tool_calls"].([]any); ok {
				if delta["extra_content"] != nil {
					t.Fatal("replay emitted before native terminal")
				}
				for _, item := range items {
					tool := chatTestMap(item)
					i := tool["index"].(float64)
					if tools[i] != nil {
						t.Fatal("duplicate call args")
					}
					tools[i] = tool
					if extra, ok := tool["extra_content"].(map[string]any); ok && extra["agy"] != nil {
						t.Fatal("partial tool replay metadata")
					}
				}
			}
		}
	}
	if text != "aa" || thought != "think" || roles[4] != 1 || roles[8] != 1 || terminals != 2 || len(tools) != 2 || tools[0]["id"] == tools[1]["id"] {
		t.Fatal("stream treated native deltas as cumulative or duplicated role/tools")
	}
	usage := frames[len(frames)-1]
	if len(chatTestChoices(usage)) != 0 || chatTestMap(usage["usage"])["total_tokens"] != float64(15) {
		t.Fatal("terminal usage frame missing or wrong")
	}
}

type chatTestByteReader struct{ value string }

func (r *chatTestByteReader) Read(p []byte) (int, error) {
	if r.value == "" {
		return 0, io.EOF
	}
	p[0], r.value = r.value[0], r.value[1:]
	return 1, nil
}

type chatTestFailedReader struct{}

func (chatTestFailedReader) Read([]byte) (int, error) { return 0, errors.New("private prompt/token") }

type chatTestFailedWriter struct{}

func (chatTestFailedWriter) Write([]byte) (int, error) { return 0, errors.New("private prompt/token") }

func TestChatResponseFailuresNeverComplete(t *testing.T) {
	valid := `{"candidates":[{"index":0,"content":{"parts":[{"text":"hi"}]},"finishReason":"STOP"}]}`
	cases := map[string]string{
		"empty":                    "",
		"missing terminal":         chatTestSSE(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}`),
		"truncated boundary":       "data: " + valid + "\n",
		"truncated line":           "data: " + valid,
		"truncated comment":        chatTestSSE(valid) + ": comment\n",
		"fake done":                chatTestSSE(`{"candidates":[{}]}`, "[DONE]"),
		"truncated json":           chatTestSSE(`{"response":`),
		"error":                    chatTestSSE(`{"error":{"message":"private prompt/token"}}`),
		"inner error":              chatTestSSE(`{"response":{"error":{"message":"private prompt/token"}}}`),
		"block":                    chatTestSSE(`{"promptFeedback":{"blockReason":"SAFETY","blockReasonMessage":"private prompt/token"}}`),
		"outer block":              chatTestSSE(`{"promptFeedback":{"blockReason":"SAFETY"},"response":{"candidates":[{"finishReason":"STOP"}]}}`),
		"unknown finish":           chatTestSSE(`{"candidates":[{"finishReason":"NEW_REASON"}]}`),
		"media":                    chatTestSSE(`{"candidates":[{"content":{"parts":[{"inlineData":{"data":"private prompt/token"}}]},"finishReason":"STOP"}]}`),
		"unknown output":           chatTestSSE(`{"candidates":[{"content":{"parts":[{"futureOutput":{}}]},"finishReason":"STOP"}]}`),
		"one candidate incomplete": chatTestSSE(`{"candidates":[{"index":1,"finishReason":"STOP"},{"index":5,"content":{"parts":[{"text":"hi"}]}}]}`),
		"continued candidate":      chatTestSSE(valid, valid),
		"post done data":           chatTestSSE(valid, "[DONE]", valid),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var dst bytes.Buffer
			err := convertChatStream(&dst, strings.NewReader(input), "gemini-test", "id", 1, true, nil)
			if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(dst.String(), "[DONE]") || strings.Contains(dst.String(), `"choices":[],"`) {
				t.Fatalf("failed stream completed or leaked error: %v, %s", err, dst.String())
			}
			frames := chatTestFrames(t, dst.String())
			if len(frames) == 0 || frames[len(frames)-1]["error"] == nil {
				t.Fatal("translation failure did not emit safe OpenAI error frame")
			}
		})
	}
	for _, source := range []io.Reader{chatTestFailedReader{}, io.MultiReader(strings.NewReader(chatTestSSE(valid)), chatTestFailedReader{})} {
		var dst bytes.Buffer
		err := convertChatStream(&dst, source, "gemini-test", "id", 1, false, nil)
		if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(dst.String(), "[DONE]") {
			t.Fatal("read failure treated as success")
		}
	}
	if err := convertChatStream(chatTestFailedWriter{}, strings.NewReader(chatTestSSE(valid)), "gemini-test", "id", 1, false, nil); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("writer failure not handled safely")
	}
}

func TestChatResponseJSONValidationAndFinish(t *testing.T) {
	for _, bad := range []string{
		`null`, `[]`, `{}`, `{"response":null}`, `{"candidates":[{}]}`,
		`{"error":{"message":"private"},"response":{"candidates":[{"finishReason":"STOP"}]}}`,
		`{"promptFeedback":{"blockReason":"SAFETY"}}`,
		`{"candidates":[{"finishReason":"OTHER"}]}`,
		`{"candidates":[{"index":-1,"finishReason":"STOP"}]}`,
		`{"candidates":[{"index":1,"finishReason":"STOP"},{"index":1,"finishReason":"STOP"}]}`,
		`{"candidates":[{"content":{"parts":[{"text":"hi","inlineData":{}}]},"finishReason":"STOP"}]}`,
		`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f","args":"{partial"}}]},"finishReason":"STOP"}]}`,
		`{"candidates":[{"content":{"parts":[{"text":null}]},"finishReason":"STOP"}]}`,
		`{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":-1}}`,
		`{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9223372036854775807,"thoughtsTokenCount":1}}`,
		`{"candidates":[{"content":{"parts":[{"thoughtSignature":"sig","futureOutput":{}}]},"finishReason":"STOP"}]}`,
	} {
		if _, err := convertChatJSON([]byte(bad), "gemini-test", "id", 1); err == nil || strings.Contains(err.Error(), "private") {
			t.Errorf("invalid JSON response accepted or leaked: %s, %v", bad, err)
		}
	}
	for _, reason := range []string{"STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"} {
		data, err := convertChatJSON([]byte(`{"candidates":[{"finishReason":"`+reason+`"}]}`), "gemini-test", "id", 1)
		if err != nil {
			t.Fatal(err)
		}
		want := "content_filter"
		if reason == "STOP" {
			want = "stop"
		}
		if reason == "MAX_TOKENS" {
			want = "length"
		}
		if chatTestMap(chatTestChoices(chatTestDecode(t, data))[0])["finish_reason"] != want {
			t.Fatal("incorrect finish mapping")
		}
	}
}

func TestChatResponseLimits(t *testing.T) {
	for name, input := range map[string]string{
		"candidates": `{"candidates":[` + strings.TrimSuffix(strings.Repeat(`{"finishReason":"STOP"},`, chatResponseMaxCandidates+1), ",") + `]}`,
		"parts":      `{"candidates":[{"content":{"parts":[` + strings.TrimSuffix(strings.Repeat(`{"thoughtSignature":"s"},`, chatResponseMaxParts+1), ",") + `]},"finishReason":"STOP"}]}`,
		"tools":      `{"candidates":[{"content":{"parts":[` + strings.TrimSuffix(strings.Repeat(`{"functionCall":{"name":"f","args":{}}},`, chatResponseMaxTools+1), ",") + `]},"finishReason":"STOP"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := convertChatJSON([]byte(input), "gemini-test", "id", 1); err == nil {
				t.Fatal("count limit was not enforced")
			}
		})
	}
	frame, err := chatResponseDecodeFrame([]byte(`{"candidates":[{"index":3,"content":{"parts":[{"text":"hello"},{"functionCall":{"name":"f","args":{}}}]}},{"index":9,"content":{"parts":[{"text":"world"}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := chatResponseNewState("gemini-test", "id", 1)
	ignore := func(int, map[string]any, any) error { return nil }
	if err := s.apply(frame, ignore); err != nil {
		t.Fatal(err)
	}
	if s.replayBytes != s.candidates[3].nativeBytes*2+s.candidates[9].nativeBytes {
		t.Fatal("aggregate budget omitted repeated tool metadata or another candidate")
	}
	more, _ := chatResponseDecodeFrame([]byte(`{"candidates":[{"index":9,"content":{"parts":[{"text":"more"}]}}]}`))
	// Put the retained-state budget at its boundary without allocating 64 MiB.
	s.replayBytes = maxEventBytes - 1
	if err := s.apply(more, ignore); err == nil {
		t.Fatal("aggregate replay limit not enforced across frames")
	}
	line := ": " + strings.Repeat("x", 8192) + "\r\n"
	readers := make([]io.Reader, maxEventBytes/len(line)+1)
	for i := range readers {
		readers[i] = strings.NewReader(line)
	}
	var dst bytes.Buffer
	err = convertChatStream(&dst, io.MultiReader(readers...), "gemini-test", "id", 1, false, nil)
	if err == nil || !strings.Contains(err.Error(), "too large") || strings.Contains(dst.String(), "[DONE]") {
		t.Fatal("aggregate multiline event limit not enforced")
	}
}

type chatTestShortWriter struct{}

func (chatTestShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestChatResponseShortWrite(t *testing.T) {
	if err := chatResponseWriteSSE(chatTestShortWriter{}, "data: {}\n\n"); err == nil {
		t.Fatal("short write reported as success")
	}
}

func TestChatResponseStreamOptionalUsageAndLineEndings(t *testing.T) {
	valid := `{"candidates":[{"content":{"parts":[{"text":"hi"}]},"finishReason":"STOP"}]}`
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		var dst bytes.Buffer
		input := strings.ReplaceAll(chatTestSSE(valid, "[DONE]"), "\n", ending)
		if err := convertChatStream(&dst, &chatTestByteReader{value: input}, "gemini-test", "id", 1, false, nil); err != nil {
			t.Fatal(err)
		}
		for _, frame := range chatTestFrames(t, dst.String()) {
			if frame["usage"] != nil {
				t.Fatal("usage emitted when not requested")
			}
		}
	}
}
