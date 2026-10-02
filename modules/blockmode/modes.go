package blockmode

import (
	"crypto/cipher"
)

type (
	AEAD      = cipher.AEAD
	Block     = cipher.Block
	BlockMode = cipher.BlockMode
	Stream    = cipher.Stream
)
