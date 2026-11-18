package main

import (
	"strings"
	"testing"
)

func TestResponsesNullableSDKDefaultsAndExactSampling(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi","store":false,"stream":null,"stream_options":null,"background":null,"truncation":null,"metadata":null,"reasoning":null,"text":null,"tool_choice":null,"parallel_tool_calls":null,"max_output_tokens":null,"temperature":null,"top_p":null}`)
	native := responsesTestMap(t, input.Gemini)
	if native["generationConfig"] != nil || native["toolConfig"] != nil || input.Stream || input.Encrypted {
		t.Fatal("nullable defaults changed model generation controls")
	}
	input = responsesTestInput(t, `{"model":"gemini-test","input":"hi","temperature":0.123456789012345678901,"top_p":0.98765432109876543210}`)
	if !strings.Contains(string(input.Gemini), `0.123456789012345678901`) || !strings.Contains(string(input.Gemini), `0.98765432109876543210`) {
		t.Fatal("sampling JSON numbers passed through float64 serialization")
	}
}

func TestResponsesRejectsDroppedReasoningFromTextOnlyOutput(t *testing.T) {
	input := responsesTestInput(t, `{"model":"gemini-test","input":"hi","include":["reasoning.encrypted_content"]}`)
	output := responsesTestJSON(t, input, `{"candidates":[{"content":{"parts":[{"text":"answer","thoughtSignature":"signed-text"}]},"finishReason":"STOP"}]}`)
	items := output["output"].([]any)
	request := map[string]any{"model": "gemini-test", "input": []any{map[string]any{"role": "user", "content": "hi"}, items[1], map[string]any{"role": "user", "content": "next"}}}
	if _, err := responsesDecodeRequest(chatRaw(request), testKey); err == nil {
		t.Fatal("identified previous output silently lost its signature carriers")
	}
	// Hand-authored text-only assistant history without output IDs remains useful.
	responsesTestInput(t, `{"model":"gemini-test","input":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"output_text","text":"manual answer"}]},{"role":"user","content":"next"}]}`)
}
