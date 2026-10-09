package hkdf

import (
	"hash"

	"github.com/flily/go-ssl/modules/hmac"
)

func Extract[H hash.Hash](h func() H, salt []byte, inputKeyMaterial []byte) []byte {
	return hmac.HMAC(h, salt, inputKeyMaterial)
}

func Expand[H hash.Hash](h func() H, prk []byte, info []byte, length int) []byte {
	hh := h()
	n := (length + hh.Size() - 1) / hh.Size()

	ts := make([][]byte, 0, n)
	last := []byte{}

	for counter := range n {
		m := make([]byte, 0, len(last)+len(info)+1)
		m = append(m, last...)
		m = append(m, info...)
		m = append(m, byte(counter+1))
		last = hmac.HMAC(h, prk, m)
		ts = append(ts, last)
	}

	result := make([]byte, 0, length)
	for _, t := range ts {
		result = append(result, t...)
	}
	return result[:length]
}
