package encoder

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func PEMEncode(name string, data []byte) []byte {
	contentLength := 4 * ((len(data) + 2) / 3)
	lines := (contentLength + 63) / 64
	size := 17 + 15 + 2*len(name) + contentLength + lines

	content := make([]byte, contentLength)
	base64.StdEncoding.Encode(content, data)

	b := bytes.NewBuffer(make([]byte, 0, size))
	_, _ = b.WriteString(fmt.Sprintf("-----BEGIN %s-----\n", name))
	for i := 0; i < contentLength; i += 64 {
		end := i + 64
		if end > contentLength {
			end = contentLength
		}

		_, _ = b.Write(content[i:end])
		_ = b.WriteByte('\n')
	}
	_, _ = b.WriteString(fmt.Sprintf("-----END %s-----", name))

	return b.Bytes()
}
