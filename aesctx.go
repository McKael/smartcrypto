package smartcrypto

import (
	"crypto/aes"
	"errors"
	"fmt"
	//"unsafe"
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

	// Transpiled algorithm
	tCtx := make([]byte, bs)
	aes128transform(3, &key[0], &in[0], &tCtx[0])

	// comp goCtx / tCtx
	fmt.Printf("goCtx: %02x\n", goCtx)
	fmt.Printf("tCtx:  %02x\n", tCtx)

	return tCtx, err
}

// This one does not work as expected
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
