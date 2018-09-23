package smartcrypto

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lssl -lcrypto
// #include "aes.h"
//
// void applySamyGOKeyTransform2(const unsigned char *tKey,
// 	unsigned char *pIn, unsigned char *pOut) {
// 	AES_128_Transform(3, tKey, pIn, pOut);
// }
import "C"

import (
	"crypto/aes"
	"errors"
	"fmt"
	"unsafe"
)

// keyTransform returns the ctx built from the input hash
func keyTransform(key []byte, in []byte) ([]byte, error) {
	bs := aes.BlockSize
	if len(in) != bs || len(key) != bs {
		return nil, errors.New("incorrect data size")
	}

	// XXX Can't find how to write a Go implementation
	goCtx, err := applySamyGOKeyTransform(key, in)
	if err != nil {
		return nil, err
	}

	// C implementation
	cCtx := make([]byte, bs)
	C.applySamyGOKeyTransform2(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		(*C.uchar)(unsafe.Pointer(&cCtx[0])),
	)

	// TODO comp goCtx / cCtx
	fmt.Printf("goCtx: %02x\n", goCtx)
	fmt.Printf("cCtx:  %02x\n", cCtx)

	return cCtx, err
}

func applySamyGOKeyTransform(key, in []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(in) != block.BlockSize() {
		return nil, errors.New("bad input size")
	}

	out := make([]byte, len(in))
	block.Encrypt(out, in)
	return out, nil
}
