package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Mirror Max's Chat accumulator: strings concatenate, opaque objects replace.
func chatAssembleStream(t *testing.T, stream string) (map[string]any, bool) {
	t.Helper()
	message := map[string]any{"role": "assistant"}
	calls := map[int]map[string]any{}
	usage := false
	for _, line := range strings.Split(stream, "\n") {
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		var frame struct {
			Error   json.RawMessage
			Choices []struct {
				Index int
				Delta map[string]any
			}
			Usage json.RawMessage
		}
		decoder := json.NewDecoder(strings.NewReader(line[6:]))
		decoder.UseNumber()
		if decoder.Decode(&frame) != nil || len(frame.Error) > 0 {
			t.Fatal("invalid/error Chat SSE")
		}
		usage = usage || len(frame.Usage) > 0
		for _, choice := range frame.Choices {
			if choice.Index != 0 {
				continue
			}
			for name, value := range choice.Delta {
				switch name {
				case "content", "reasoning_content":
					if text, ok := value.(string); ok {
						old, _ := message[name].(string)
						message[name] = old + text
					}
				case "tool_calls":
					for _, item := range value.([]any) {
						delta := item.(map[string]any)
						number, _ := delta["index"].(json.Number).Int64()
						index := int(number)
						call := calls[index]
						if call == nil {
							call = map[string]any{}
							calls[index] = call
						}
						for key, value := range delta {
							if key == "index" {
								continue
							}
							if key == "function" {
								function, _ := call[key].(map[string]any)
								if function == nil {
									function = map[string]any{}
									call[key] = function
								}
								for k, v := range value.(map[string]any) {
									old, _ := function[k].(string)
									function[k] = old + v.(string)
								}
							} else {
								call[key] = value
							}
						}
					}
				default:
					message[name] = value
				}
			}
		}
	}
	if len(calls) > 0 {
		list := make([]any, len(calls))
		for index, call := range calls {
			list[index] = call
		}
		message["tool_calls"] = list
	}
	return message, usage
}

func TestChatStreamToNativeReplayRoundTrip(t *testing.T) {
	frames := chatTestSSE(`{"response":{"candidates":[{"index":0,"content":{"role":"model","parts":[{"thought":true,"text":"thinking","thoughtSignature":"thought-sig"},{"text":"Check "}]}}]}}`, `{"response":{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"this"},{"functionCall":{"name":"probe","args":{"large":9007199254740993},"id":"native-id"},"thoughtSignature":"call-sig"},{"thoughtSignature":"tail-sig"}]},"finishReason":"STOP"}]}}`)
	var out bytes.Buffer
	if err := convertChatStream(&out, strings.NewReader(frames), "gemini-test", "id", 1, true, func() {}); err != nil {
		t.Fatal(err)
	}
	message, usage := chatAssembleStream(t, out.String())
	if !usage {
		t.Fatal("usage missing")
	}
	// A client retaining only the tool metadata (not message-level extra_content) still replays exactly.
	delete(message, "extra_content")
	body := map[string]any{"model": "gemini-test", "messages": []any{map[string]any{"role": "user", "content": "check"}, message, map[string]any{"role": "tool", "tool_call_id": "native-id", "content": "ok"}}}
	input, err := decodeChatRequest(chatRaw(body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(input.Gemini), `9007199254740993`) {
		t.Fatal("large native tool integer lost precision during replay")
	}
	for _, want := range []string{"thought-sig", "call-sig", "tail-sig", "native-id"} {
		if !strings.Contains(string(input.Gemini), want) {
			t.Errorf("lost replay carrier %s", want)
		}
	}
	// A client dropping both metadata carriers gets a useful request error, not invented signatures.
	delete(message["tool_calls"].([]any)[0].(map[string]any), "extra_content")
	if _, err := decodeChatRequest(chatRaw(body)); err == nil {
		t.Fatal("lost tool signature was silently accepted")
	}
}
