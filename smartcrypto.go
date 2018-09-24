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
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

// HelloData contains data to generate the ServerHello and check the ClientHello
type HelloData struct {
	UserID, PIN string // User-provided
	Key, Ctx    []byte // Calculated by GenerateServerHello
}

// GenerateServerHello builds the Server Hello hex string
func GenerateServerHello(hello *HelloData) ([]byte, error) {
	// Basic userID length check
	if len(hello.UserID) < 1 || len(hello.UserID) > 96 {
		return nil, errors.New("invalid UserID size")
	}

	// Expected ServerHello length
	expectedLength := 10 + 1 + (4 + len(hello.UserID) + 128) + 5

	pinHash := sha1.Sum([]byte(hello.PIN))
	//fmt.Printf("PIN hash: %02x\n", pinHash)

	hello.Key = pinHash[:16]

	encrypted, err := aesEncryptCBC(hello.Key, publicKey)
	if err != nil {
		panic(err.Error())
	}
	//fmt.Printf("encrypted: %02x\n", encrypted)

	swapped, err := aesEncryptECB(wbKey, encrypted)
	if err != nil {
		return nil, errors.Wrap(err, "aesEncryptECB failed")
	}
	swapped = swapped[:128]
	//fmt.Printf("swapped: %02x\n", swapped)

	// Compute ctx
	var dataBuf bytes.Buffer
	binary.Write(&dataBuf, binary.BigEndian, uint32(len(hello.UserID)))
	dataBuf.WriteString(hello.UserID)
	dataBuf.Write(swapped)

	dataHash := sha1.Sum(dataBuf.Bytes()) // ctx
	hello.Ctx = dataHash[:]

	//fmt.Printf("data hash (ctx): %02x\n", dataHash)

	// dataBuf will contain the ServerHello bytes
	var serverHelloBuf bytes.Buffer

	// Header
	serverHelloBuf.Write([]byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Data Size
	//fmt.Printf("DBG data len=%d\n", dataBuf.Len())
	binary.Write(&serverHelloBuf, binary.BigEndian, uint32(dataBuf.Len()))
	// Data
	serverHelloBuf.Write(dataBuf.Bytes())
	// Footer
	serverHelloBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})

	//fmt.Printf("server hello: %02X\n", serverHelloBuf.Bytes())

	if serverHelloBuf.Len() != expectedLength {
		return nil, errors.Errorf("unexpected ServerHello length (got %d, want %d)",
			serverHelloBuf.Len(), expectedLength)
	}

	return serverHelloBuf.Bytes(), nil
}

// ParseClientHello parses the client message and checks it's valid
// Returns (SKPrime, ctx) and an error if it failed.
func ParseClientHello(hello HelloData, clientHello string) ([]byte, []byte, error) {
	const gxSize = 0x80

	data, err := hex.DecodeString(clientHello)
	if err != nil {
		return nil, nil, errors.New("could not decode ClientHello string")
	}

	// Check the CH length looks acceptable
	// >= 7[=header]+4[=int32]*2+128[=gx]+20[=sha]+(1+4)[=flags]+len(userID)
	if len(data) < 164 {
		return nil, nil, errors.New("ClientHello string looks too short")
	}

	dataBuf := bytes.NewReader(data)

	header := make([]byte, 7)
	if n, _ := dataBuf.Read(header); n != 7 {
		panic("failed to read ClientHello header")
	}

	if bytes.Compare(header, []byte{1, 1, 0, 0, 0, 0, 0}) != 0 {
		return nil, nil, errors.New("unexpected ClientHello header")
	}

	var length, payloadSize uint32

	// data[7:11]
	if err := binary.Read(dataBuf, binary.BigEndian, &payloadSize); err != nil {
		panic("failed to read ClientHello's data length")
	}
	//println("len1: ", payloadSize)

	// data[11:15]
	if err := binary.Read(dataBuf, binary.BigEndian, &length); err != nil {
		return nil, nil, errors.New("could not read user-id len")
	}
	//println("len2: ", length)
	if length+152 != payloadSize { // check uid len looks good
		return nil, nil, errors.New("invalid client ID length")
	}

	clientUserID := make([]byte, length)
	if n, _ := dataBuf.Read(clientUserID); n != int(length) {
		panic("failed to read ClientHello's user-id")
	}
	//println("client UserID:", string(clientUserID))

	if string(clientUserID) != hello.UserID {
		// I'm not sure this is actually an error
		return nil, nil, fmt.Errorf("client user-id differs from ours: `%s`",
			string(clientUserID))
	}

	encWBGx := make([]byte, gxSize)
	if n, _ := dataBuf.Read(encWBGx); n != gxSize {
		panic("failed to read ClientHello's data")
	}
	//fmt.Printf("encWBGx: %02x\n", encWBGx)

	encGx, err := aesDecryptECB(wbKey, encWBGx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aesDecryptECB failed")
	}
	//fmt.Printf("encGx: %02x\n", encGx)

	gx, err := aesDecryptCBC(hello.Key, encGx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aesDecryptCBC failed")
	}
	//fmt.Printf("gx: %02x\n", gx)

	bnGx := new(big.Int)
	bnPrime := new(big.Int)
	bnPrivateKey := new(big.Int)
	bnSecret := new(big.Int)

	bnGx.SetBytes(gx)
	bnPrime.SetBytes(prime)
	bnPrivateKey.SetBytes(privateKey)
	bnSecret.Exp(bnGx, bnPrivateKey, bnPrime)

	secret := bnSecret.Bytes()
	//fmt.Printf("secret: %02x\n", secret)

	clientHash := make([]byte, 20)
	if n, _ := dataBuf.Read(clientHash); n != len(clientHash) {
		panic("failed to read ClientHello's hash")
	}
	//fmt.Printf("client hash: %02x\n", clientHash)

	// Flags
	if flag, err := dataBuf.ReadByte(); err != nil {
		panic("failed to read ClientHello's flag #1")
	} else {
		//fmt.Printf("client flag #1: %02x\n", flag)
		if flag != 0 {
			return nil, nil, errors.New("Client Hello parsing failed: flag #1 is not null")
		}
	}

	var clientFlag2 uint32
	if err := binary.Read(dataBuf, binary.BigEndian, &clientFlag2); err != nil {
		panic("failed to read ClientHello's flag #2")
	}
	//fmt.Printf("client flag #2: %02x\n", clientFlag2)
	if clientFlag2 != 0 {
		return nil, nil, errors.New("Client Hello parsing failed: flag #2 is not null")
	}

	// Hashes
	h := sha1.New()
	h.Write([]byte(hello.UserID))
	h.Write(secret)
	calculatedHash := h.Sum(nil)
	//fmt.Printf("calculated hash #1: %02x\n", calculatedHash)

	if bytes.Compare(calculatedHash, clientHash) != 0 {
		return nil, nil, errors.New("bad PIN")
	}

	// PIN is OK;
	// Compute key and hash

	h = sha1.New()
	h.Write([]byte(clientUserID)) // can both differ?
	h.Write([]byte(hello.UserID))
	h.Write(gx)
	h.Write(publicKey)
	h.Write(secret)
	calculatedHash = h.Sum(nil) // skprime
	skprime := calculatedHash[:]
	//fmt.Printf("calculated hash #2 (skprime): %02x\n", skprime)

	skprimeHash := sha1.Sum(skprime[:21])
	//fmt.Printf("skprimehash: %02x\n", skprimeHash)

	//fmt.Printf("transKey: %02x\n", transKey)

	ctx, err := keyTransform(transKey, skprimeHash[:16])
	if err != nil {
		return nil, nil, errors.Wrap(err, "KeyTransform failed")
	}

	return skprime, ctx, nil
}

// GenerateServerAcknowledge builds the ServerAcknowledge data string
func GenerateServerAcknowledge(skprime []byte) (string, error) {
	skprime = append(skprime, '\x01')
	bs := sha1.Sum([]byte(skprime))
	return "0103000000000000000014" + fmt.Sprintf("%X", bs) + "0000000000", nil
}

// ParseClientAcknowledge checks the ClientAcknowledge data
func ParseClientAcknowledge(clientAck string, skprime []byte) error {
	if len(clientAck) < 72 {
		return errors.New("incorrect client acknowledge length")
	}
	skprime = append(skprime, '\x02')
	bs := sha1.Sum([]byte(skprime))
	expectedClientAckData := fmt.Sprintf("%X", bs) + "0000000000"

	if expectedClientAckData == clientAck[22:] {
		return nil
	}
	return errors.New("incorrect client acknowledge")
}
