package encoding

import (
	"errors"
)

var (
	ErrCertletErrorBase   = errors.New("certlet: base error")
	ErrDataTypeNotSupport = errors.New("certlet: data type not support")
)
