package main

import (
	"bytes"
	"testing"
)

func TestSecretFilterAcrossEveryChunkBoundary(t *testing.T) {
	secrets := [][]byte{[]byte("test-private-model-token"), []byte("test-private-proof"), nil}
	input := []byte("data: {\"text\":\"test-private-model-token / test-private-proof\"}\n\n")
	want := []byte("data: {\"text\":\"[REDACTED] / [REDACTED]\"}\n\n")
	for size := 1; size <= len(input); size++ {
		filter := secretFilter{secrets: secrets}
		var output []byte
		for start := 0; start < len(input); start += size {
			output = append(output, filter.push(input[start:min(start+size, len(input))], false)...)
		}
		output = append(output, filter.push(nil, true)...)
		if !bytes.Equal(output, want) || len(filter.pending) != 0 {
			t.Fatalf("credential leaked with chunk size %d: %s", size, output)
		}
	}
	filter := secretFilter{secrets: secrets}
	ordinary := []byte("data: {\"delta\":\"text\"}\n\n")
	if !bytes.Equal(filter.push(ordinary, false), ordinary) || len(filter.pending) != 0 {
		t.Fatal("ordinary SSE frames were delayed or changed")
	}
}
