package hkdf

type HKDF interface {
	Extract(salt []byte, inputKeyMaterial []byte) ([]byte, error)
	Expand(prk []byte, info []byte, length int) ([]byte, error)
}
