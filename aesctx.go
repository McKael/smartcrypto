// Copyright © 2018 Mikael Berthe <mikael@lilotux.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package smartcrypto

import (
	"crypto/aes"
	"errors"
)

// keyTransform returns the ctx built from the input hash
func keyTransform(key []byte, in []byte) ([]byte, error) {
	bs := aes.BlockSize
	if len(in) != bs || len(key) != bs {
		return nil, errors.New("incorrect data size")
	}

	// XXX Can't find how to write a Go implementation
	/*
		goCtx, err := applySamyGOKeyTransform(key, in)
		if err != nil {
			return nil, err
		}
	*/

	// Transpiled algorithm
	tCtx := make([]byte, bs)
	aes128transform(3, &key[0], &in[0], &tCtx[0])

	/*
		fmt.Printf("goCtx: %02x\n", goCtx)
		fmt.Printf("tCtx:  %02x\n", tCtx)
	*/

	return tCtx, nil
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
