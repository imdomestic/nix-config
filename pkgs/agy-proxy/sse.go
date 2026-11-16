package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const maxEventBytes = 64 << 20

// Unwrap only the Cloud Code envelope; never rebuild candidates or parts.
func unwrapResponse(data []byte) ([]byte, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("invalid upstream JSON")
	}
	if inner, ok := object["response"]; ok {
		if !json.Valid(inner) || bytes.Equal(bytes.TrimSpace(inner), []byte("null")) {
			return nil, errors.New("invalid upstream response")
		}
		return inner, nil
	}
	// Error and metadata-only frames are not replaced by synthetic success.
	return data, nil
}

func unwrapSSE(dst io.Writer, src io.Reader, flush func()) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 64<<10), maxEventBytes)
	var lines []string
	size := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := writeEvent(dst, lines); err != nil {
				return err
			}
			if _, err := io.WriteString(dst, "\n"); err != nil {
				return err
			}
			flush()
			lines = nil
			size = 0
			continue
		}
		size += len(line) + 1
		if size > maxEventBytes {
			return errors.New("upstream event too large")
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(lines) != 0 {
		// A missing SSE event boundary is a truncated stream, not STOP.
		return io.ErrUnexpectedEOF
	}
	return nil
}

func writeEvent(dst io.Writer, lines []string) error {
	var data []string
	firstData := -1
	for i, line := range lines {
		if line == "data" || len(line) >= 5 && line[:5] == "data:" {
			if firstData < 0 {
				firstData = i
			}
			value := ""
			if len(line) >= 5 {
				value = line[5:]
				if len(value) > 0 && value[0] == ' ' {
					value = value[1:]
				}
			}
			data = append(data, value)
		}
	}
	payload := []byte(strings.Join(data, "\n"))
	if firstData >= 0 && len(payload) > 0 && !bytes.Equal(payload, []byte("[DONE]")) {
		var err error
		payload, err = unwrapResponse(payload)
		if err != nil {
			return err
		}
		// RawMessage can span lines; every line must remain an SSE data line.
		var compact bytes.Buffer
		if err := json.Compact(&compact, payload); err != nil {
			return err
		}
		payload = compact.Bytes()
	}
	for i, line := range lines {
		isData := line == "data" || len(line) >= 5 && line[:5] == "data:"
		if isData {
			if i != firstData {
				continue
			}
			line = "data: " + string(payload)
		}
		if _, err := io.WriteString(dst, line+"\n"); err != nil {
			return err
		}
	}
	return nil
}
