// Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
// rights reserved.
//
// License to copy and use this software is granted for
// non-commercial Internet Privacy-Enhanced Mail provided that it is
// identified as the "RSA Data Security, Inc. MD2 Message Digest
// Algorithm" in all material mentioning or referencing this software
// or this function.
//
// RSA Data Security, Inc. makes no representations concerning either
// the merchantability of this software or the suitability of this
// software for any particular purpose. It is provided "as is"
// without express or implied warranty of any kind.
//
// These notices must be retained in any copies of any part of this
// documentation and/or software.

// Package md2 implements the MD2 hash algorithm as defined in RFC 1319.
// Codes are implemented based on the original C implementation
// by RSA Data Security, Inc.
//
// Deprecated: MD2 was published in 1992 as as an Informational RFC.
// Since its publication, MD2 has been shown to not be collision-free,
// albeit successful collision attacks for properly implemented MD2 are not
// that damaging. Successful pre-image and second pre-image attacks against
// MD2 have been shown. MD2 is obsoleted by RFC 6149 and MUST NOT be used for
// security purposes. Only for compatibility or educational purposes.
package md2

import (
	"hash"
	"slices"
)

const (
	MD2OutputSize = 16
	MD2BlockSize  = 16
)

type MD2State struct {
	state    [16]byte
	checksum [16]byte
	count    int
	buffer   [16]byte
}

var (
	// Permutation of 0..255 constructed from the digits of pi. It gives a
	// "random" nonlinear byte substitution operation.
	piSubstitution = [256]byte{
		41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
		19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
		76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
		138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
		245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
		148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
		39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
		181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
		150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
		112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
		96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
		85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
		234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
		129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
		8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
		203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
		166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
		31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
	}

	padding = [17][]byte{
		{},
		{0x01},
		{0x02, 0x02},
		{0x03, 0x03, 0x03},
		{0x04, 0x04, 0x04, 0x04},
		{0x05, 0x05, 0x05, 0x05, 0x05},
		{0x06, 0x06, 0x06, 0x06, 0x06, 0x06},
		{0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07},
		{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08},
		{0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09},
		{0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a},
		{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
		{0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c},
		{0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d},
		{0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e},
		{0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f},
		{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10},
	}
)

func md2Memset(b []byte, value byte) {
	_ = slices.Replace(b, 0, len(b), value)
}

// NewMD2State initialize states.
// from `void MD2Init(context) MD2_CTX *context`
// MD2 initialization. Begins an MD2 operation, writing a new context.
func NewMD2State() *MD2State {
	s := &MD2State{}
	s.Reset()

	return s
}

// New returns a new hash.Hash computing the MD2 checksum.
func New() hash.Hash {
	return NewMD2State()
}

func (s *MD2State) Reset() {
	s.count = 0
	md2Memset(s.state[:], 0)
	md2Memset(s.checksum[:], 0)
	md2Memset(s.buffer[:], 0)
}

// MD2Transform performs the core MD2 transformation on a 16-byte block.
//
// MD2 basic transformation. Transforms state and updates checksum
// based on block.
//
// static void MD2Transform (state, checksum, block)
// unsigned char state[16];
// unsigned char checksum[16];
// unsigned char block[16];
func MD2Transform(state []byte, checksum []byte, block []byte) {
	// unsigned int i, j, t;
	// unsigned char x[48];
	var x [48]byte

	/* Form encryption block from state, block, state ^ block.
	 */
	// MD2_memcpy ((POINTER)x, (POINTER)state, 16);
	copy(x[:16], state[:])
	// MD2_memcpy ((POINTER)x+16, (POINTER)block, 16);
	copy(x[16:32], block[:])
	// for (i = 0; i < 16; i++)
	for i := range 16 {
		// x[i+32] = state[i] ^ block[i];
		x[i+32] = state[i] ^ block[i]
	}

	/* Encrypt block (18 rounds).
	 */
	// t = 0;
	t := 0
	// for (i = 0; i < 18; i++) {
	for i := range 18 {
		// for (j = 0; j < 48; j++)
		for j := range 48 {
			// t = x[j] ^= PI_SUBST[t];
			x[j] ^= piSubstitution[t]
			t = int(x[j])
		}

		// t = (t + i) & 0xff;
		t = (t + i) & 0xff
		// }
	}

	/* Save new state */
	// MD2_memcpy ((POINTER)state, (POINTER)x, 16);
	copy(state[:], x[:16])

	/* Update checksum.
	 */
	// t = checksum[15];
	t = int(checksum[15])
	// for (i = 0; i < 16; i++)
	for i := range 16 {
		// t = checksum[i] ^= PI_SUBST[block[i] ^ t];
		checksum[i] ^= piSubstitution[block[i]^byte(t)]
		t = int(checksum[i])
	}

	/* Zeroize sensitive information.
	 */
	// MD2_memset ((POINTER)x, 0, sizeof (x));
	md2Memset(x[:], 0)
}

// Update processes the input data and updates the MD2 state.
//
// MD2 block update operation. Continues an MD2 message-digest
// operation, processing another message block, and updating the
// context.
//
// void MD2Update (context, input, inputLen)
// MD2_CTX *context;                                        /* context */
// unsigned char *input;                                /* input block */
// unsigned int inputLen;                     /* length of input block */
func (s *MD2State) Update(input []byte) {
	// unsigned int i, index, partLen;

	/* Update number of bytes mod 16 */
	// index = context->count;
	index := s.count
	// context->count = (index + inputLen) & 0xf;
	s.count = (index + len(input)) & 0x0f

	// partLen = 16 - index;
	partLen := 16 - index

	i := 0
	/* Transform as many times as possible.
	 */
	//   if (inputLen >= partLen) {
	if len(input) >= partLen {
		// MD2_memcpy
		//   ((POINTER)&context->buffer[index], (POINTER)input, partLen);
		copy(s.buffer[index:], input[:partLen])

		// MD2Transform (context->state, context->checksum, context->buffer);
		MD2Transform(s.state[:], s.checksum[:], s.buffer[:])

		// for (i = partLen; i + 15 < inputLen; i += 16)
		for i = partLen; i+15 < len(input); i += 16 {
			// MD2Transform (context->state, context->checksum, &input[i]);
			MD2Transform(s.state[:], s.checksum[:], input[i:i+16])
			// index = 0;
			index = 0
		}
		// }
	} else {
		// i = 0;
		i = 0
	}

	/* Buffer remaining input */
	// MD2_memcpy
	//   ((POINTER)&context->buffer[index], (POINTER)&input[i],
	//    inputLen-i);
	copy(s.buffer[index:], input[i:])
}

// Final completes the MD2 hash computation and returns the final digest.
//
// MD2 finalization. Ends an MD2 message-digest operation, writing the
// message digest and zeroizing the context.
//
// void MD2Final (digest, context)
// unsigned char digest[16];                         /* message digest */
// MD2_CTX *context;                                        /* context */
func (s *MD2State) Final() [16]byte {
	// unsigned int index, padLen;

	/* Pad out to multiple of 16.
	 */
	// index = context->count;
	index := s.count
	// padLen = 16 - index;
	padLen := 16 - index
	// MD2Update (context, PADDING[padLen], padLen);
	s.Update(padding[padLen])

	/* Extend with checksum */
	// MD2Update (context, context->checksum, 16);
	s.Update(s.checksum[:])

	/* Store state in digest */
	// MD2_memcpy ((POINTER)digest, (POINTER)context->state, 16);
	var digest [16]byte
	copy(digest[:], s.state[:])

	// /* Zeroize sensitive information.
	//
	//	*/
	//
	// MD2_memset ((POINTER)context, 0, sizeof (*context));
	s.Reset()

	return digest
}

func (s *MD2State) Write(p []byte) (n int, err error) {
	s.Update(p)
	return len(p), nil
}

func (s *MD2State) Sum(b []byte) []byte {
	digest := s.Final()
	return append(b, digest[:]...)
}

func (s *MD2State) Size() int {
	return MD2OutputSize
}

func (s *MD2State) BlockSize() int {
	return MD2BlockSize
}

func Sum(input []byte) []byte {
	s := NewMD2State()
	s.Update(input)

	result := s.Final()
	return result[:]
}
