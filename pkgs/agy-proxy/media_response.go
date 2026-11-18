package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var errMediaResponse = errors.New("invalid or incomplete upstream media response")

func decodeMediaResponse(data []byte, image bool) (string, []mediaFile, error) {
	var object map[string]json.RawMessage
	for level := 0; level < 2; level++ {
		if json.Unmarshal(data, &object) != nil || object == nil {
			return "", nil, errMediaResponse
		}
		if value, ok := object["error"]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return "", nil, errMediaResponse
		}
		if value, ok := object["promptFeedback"]; ok {
			var feedback struct {
				Block  string `json:"blockReason"`
				Safety []struct {
					Blocked bool `json:"blocked"`
				} `json:"safetyRatings"`
			}
			if json.Unmarshal(value, &feedback) != nil || feedback.Block != "" {
				return "", nil, errMediaResponse
			}
			for _, rating := range feedback.Safety {
				if rating.Blocked {
					return "", nil, errMediaResponse
				}
			}
		}
		if inner, ok := object["response"]; ok && level == 0 {
			data, object = inner, nil
			continue
		}
		break
	}
	if _, err := chatResponseBoundArray(object["candidates"], 1, nil); err != nil {
		return "", nil, errMediaResponse
	}
	var candidates []struct {
		Index   *int   `json:"index"`
		Finish  string `json:"finishReason"`
		Content struct {
			Role  string          `json:"role"`
			Parts json.RawMessage `json:"parts"`
		} `json:"content"`
		Safety []struct {
			Blocked bool `json:"blocked"`
		} `json:"safetyRatings"`
	}
	if json.Unmarshal(object["candidates"], &candidates) != nil || len(candidates) != 1 {
		return "", nil, errMediaResponse
	}
	candidate := candidates[0]
	if candidate.Finish != "STOP" || candidate.Index != nil && *candidate.Index != 0 || candidate.Content.Role != "" && candidate.Content.Role != "model" {
		return "", nil, errMediaResponse
	}
	for _, rating := range candidate.Safety {
		if rating.Blocked {
			return "", nil, errMediaResponse
		}
	}
	var text strings.Builder
	var images []mediaFile
	_, err := chatResponseBoundArray(candidate.Content.Parts, mediaMaxParts, func(raw json.RawMessage) error {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return errMediaResponse
		}
		for key := range fields {
			switch key {
			case "text", "inlineData", "thought", "thoughtSignature":
			default:
				return errMediaResponse
			}
		}
		var part struct {
			Text      *string `json:"text"`
			Thought   bool    `json:"thought"`
			Signature string  `json:"thoughtSignature"`
			Inline    *struct {
				MIME string `json:"mimeType"`
				Data string `json:"data"`
			} `json:"inlineData"`
		}
		if json.Unmarshal(raw, &part) != nil || part.Text != nil && part.Inline != nil {
			return errMediaResponse
		}
		if part.Text == nil && part.Inline == nil && part.Signature == "" {
			return errMediaResponse
		}
		// Never expose native thought text as a transcript or revised prompt.
		if part.Thought {
			return nil
		}
		if part.Text != nil {
			text.WriteString(*part.Text)
		}
		if part.Inline != nil {
			if !image || len(images) >= 1 || len(part.Inline.Data) > base64.StdEncoding.EncodedLen(mediaMaxFile) {
				return errMediaResponse
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(part.Inline.Data)
			if err != nil || len(decoded) == 0 || len(decoded) > mediaMaxFile || !mediaImageMIME(part.Inline.MIME, decoded) {
				return errMediaResponse
			}
			images = append(images, mediaFile{part.Inline.MIME, decoded})
		}
		return nil
	})
	if err != nil || image && len(images) != 1 || !image && strings.TrimSpace(text.String()) == "" {
		return "", nil, errMediaResponse
	}
	return text.String(), images, nil
}
