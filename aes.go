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
	"bytes"
	"crypto/aes"
	"crypto/cipher"

	"github.com/pkg/errors"
)

func aesEncryptECB(key, plaindata []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	// Add padding
	padding := bs - len(plaindata)%bs
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaindata = append(plaindata, padtext...)

	// Encrypt
	ciphertext := make([]byte, len(plaindata))
	for cipherrange := ciphertext; len(plaindata) > 0; {
		block.Encrypt(cipherrange, plaindata[:bs])
		plaindata = plaindata[bs:]
		cipherrange = cipherrange[bs:]
	}

	return ciphertext, nil
}

func aesDecryptECB(key, cipherdata []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	if len(cipherdata)%bs != 0 {
		return nil, errors.New("encrypted text does not have full blocks")
	}

	// Decrypt
	plaindata := make([]byte, len(cipherdata))
	for plainrange := plaindata; len(cipherdata) > 0; {
		block.Decrypt(plainrange, cipherdata[:bs])
		cipherdata = cipherdata[bs:]
		plainrange = plainrange[bs:]
	}

	// There is no padding
	return plaindata, nil
}

// Shamelessly copy-pasted from https://stackoverflow.com/a/50762567
func aesEncryptCBC(key, plaindata []byte) ([]byte, error) {
	if len(plaindata)%aes.BlockSize != 0 {
		return nil, errors.New("plaindata is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // XXX
	}
	cipherdata := make([]byte, len(plaindata))
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherdata, plaindata)
	return cipherdata, nil
}

func aesDecryptCBC(key, cipherdata []byte) ([]byte, error) {
	if len(cipherdata)%aes.BlockSize != 0 {
		return nil, errors.New("encrypted text does not have full blocks")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // XXX
	}
	plaindata := make([]byte, len(cipherdata))
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaindata, cipherdata)
	return plaindata, nil
}
