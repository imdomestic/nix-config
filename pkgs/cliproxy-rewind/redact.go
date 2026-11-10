package main

import "bytes"

// Keep only a possible credential prefix between chunks; never delay whole SSE frames.
type secretFilter struct {
	secrets [][]byte
	pending []byte
}

func (f *secretFilter) push(part []byte, final bool) []byte {
	data := append(f.pending, part...)
	var out []byte
	for {
		at := -1
		var matched []byte
		for _, secret := range f.secrets {
			if len(secret) == 0 {
				continue
			}
			if index := bytes.Index(data, secret); index >= 0 && (at == -1 || index < at || (index == at && len(secret) > len(matched))) {
				at, matched = index, secret
			}
		}
		if at < 0 {
			break
		}
		out = append(out, data[:at]...)
		out = append(out, "[REDACTED]"...)
		data = data[at+len(matched):]
	}
	keep := 0
	if !final {
		for _, secret := range f.secrets {
			for n := min(len(secret)-1, len(data)); n > keep; n-- {
				if bytes.Equal(data[len(data)-n:], secret[:n]) {
					keep = n
					break
				}
			}
		}
	}
	out = append(out, data[:len(data)-keep]...)
	f.pending = bytes.Clone(data[len(data)-keep:])
	return out
}
