package blockmode

// GCM (Galois/Counter Mode) implementation.
// reference: NIST SP 800-38D

import (
	"crypto/cipher"
)

const (
	GCMStandardNonceSize = 12
	GCMTagSize           = 16
)

var (
	gcmConstR = [16]byte{
		0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

type gcmCounter [16]byte

func newGCMCounter(nonce []byte) gcmCounter {
	var c gcmCounter
	copy(c[:], nonce)
	c[15] = 1
	return c
}

func (c *gcmCounter) Incr() {
	carry := byte(1)

	for i := 15; i >= 12; i-- {
		c[i] += carry
		if c[i] == 0 && carry != 0 {
			carry = 1
		} else {
			carry = 0
		}
	}
}

func gcmProduct(x []byte, y []byte) {
	var z [16]byte
	var yy [16]byte
	copy(yy[:], y)

	for i := 0; i < 128; i++ {
		if bitn(x, i) == 1 {
			xor(z[:], yy[:])
		}

		xorFlag := (yy[15] & 1) == 1
		lrshift(yy[:])
		if xorFlag {
			xor(yy[:], gcmConstR[:])
		}
	}

	copy(x, z[:])
}

type gcmGHashState struct {
	H [16]byte
	Y [16]byte
}

func newGHashState(H []byte) *gcmGHashState {
	s := &gcmGHashState{}
	copy(s.H[:], H)
	return s
}

func (s *gcmGHashState) Write(data []byte) {
	blockSize := 16

	for i := 0; i < len(data); i += blockSize {
		size := min(blockSize, len(data)-i)
		xor(s.Y[:], data[i:i+size])
		gcmProduct(s.Y[:], s.H[:])
	}
}

func (s *gcmGHashState) WriteUint64s(a uint64, b uint64) {
	s.Y[0] ^= byte((a >> 56) & 0xff)
	s.Y[1] ^= byte((a >> 48) & 0xff)
	s.Y[2] ^= byte((a >> 40) & 0xff)
	s.Y[3] ^= byte((a >> 32) & 0xff)
	s.Y[4] ^= byte((a >> 24) & 0xff)
	s.Y[5] ^= byte((a >> 16) & 0xff)
	s.Y[6] ^= byte((a >> 8) & 0xff)
	s.Y[7] ^= byte((a >> 0) & 0xff)
	s.Y[8] ^= byte((b >> 56) & 0xff)
	s.Y[9] ^= byte((b >> 48) & 0xff)
	s.Y[10] ^= byte((b >> 40) & 0xff)
	s.Y[11] ^= byte((b >> 32) & 0xff)
	s.Y[12] ^= byte((b >> 24) & 0xff)
	s.Y[13] ^= byte((b >> 16) & 0xff)
	s.Y[14] ^= byte((b >> 8) & 0xff)
	s.Y[15] ^= byte((b >> 0) & 0xff)

	gcmProduct(s.Y[:], s.H[:])
}

type gcmCTR struct {
	block   cipher.Block
	counter gcmCounter
}

func newGCMCtr(block cipher.Block, counter gcmCounter) *gcmCTR {
	c := &gcmCTR{
		block:   block,
		counter: counter,
	}

	return c
}

func (c *gcmCTR) Incr() {
	c.counter.Incr()
}

func (c *gcmCTR) XORKeyStream(dst, src []byte) {
	bs := c.block.BlockSize()
	key := make([]byte, bs)

	for i := 0; i < len(src); i += bs {
		size := min(bs, len(src)-i)
		c.block.Encrypt(key, c.counter[:])
		copy(dst[i:i+size], src[i:i+size])
		xor(dst[i:i+size], key[:size])
		c.counter.Incr()
	}
}

type gcmInfo struct {
	block         cipher.Block
	nonceSize     int
	tagSize       int
	encryptedZero []byte
}

func NewGCM(block cipher.Block) (cipher.AEAD, error) {
	state := &gcmInfo{
		block:         block,
		nonceSize:     GCMStandardNonceSize,
		tagSize:       GCMTagSize,
		encryptedZero: make([]byte, block.BlockSize()),
	}

	block.Encrypt(state.encryptedZero, state.encryptedZero)
	return state, nil
}

func (g *gcmInfo) NonceSize() int {
	return g.nonceSize
}

func (g *gcmInfo) Overhead() int {
	return g.tagSize
}

func (g *gcmInfo) Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte {
	head, tail := sliceForAppend(dst, len(plaintext)+g.tagSize)

	j0 := newGCMCounter(nonce)
	h := newGHashState(g.encryptedZero)

	h.Write(additionalData)

	ctrData := newGCMCtr(g.block, j0)
	ctrData.Incr()
	ctrData.XORKeyStream(tail, plaintext)

	h.Write(tail[:len(plaintext)])
	h.WriteUint64s(uint64(len(additionalData))*8, uint64(len(plaintext))*8)

	ctrTag := newGCMCtr(g.block, j0)
	ctrTag.XORKeyStream(tail[len(plaintext):], h.Y[:])

	return head
}

func (g *gcmInfo) Open(dst []byte, nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	return nil, nil
}
