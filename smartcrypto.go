package smartcrypto

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lssl -lcrypto
// #include <stdio.h> // for fflush
// #include <stdlib.h>
// #include "crypto.h"
import "C"
import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/pkg/errors"
)

// HelloData contains data to generate the ServerHello and check the ClientHello
type HelloData struct {
	UserID, PIN string // User-provided
	Key, Ctx    []byte // Calculated by GenerateServerHello
}

// GenerateServerHello builds the Server Hello hex string
func GenerateServerHello(hello *HelloData) ([]byte, error) {
	if len(hello.UserID) < 1 || len(hello.UserID) > 96 {
		// Arbitrary length check
		return nil, errors.New("invalid UserID size")
	}

	// Expected ServerHello length XXX
	expectedLength := 10 + 1 + (4 + len(hello.UserID) + 128) + 5

	// C version
	cUserID := C.CString(hello.UserID)
	cPin := C.CString(hello.PIN)

	bufSize := 2 * expectedLength

	serverHello := C.malloc(C.sizeof_char * (C.ulong)(bufSize))
	defer C.free(unsafe.Pointer(serverHello))

	ctx := make([]byte, 20)
	key := make([]byte, 16)

	// data digest "hash" is (20B*2) long
	// "AES key" hash is (16B*2) long
	n := C.generateServerHello(cUserID, cPin,
		(*C.char)(serverHello), (C.ulong)(expectedLength),
		(*C.char)(unsafe.Pointer(&key[0])),
		(*C.char)(unsafe.Pointer(&ctx[0])))
	//C.fflush(C.stdout) // for C debug messages

	hl := int(n)
	if hl < 0 {
		return nil, errors.New("generateServerHello() failed")
	}
	if hl != expectedLength { // XXX keep
		return nil, errors.New("unexpected Hello length")
	}

	hello.Key = key
	hello.Ctx = ctx

	serverHelloBytes := C.GoBytes(unsafe.Pointer(serverHello), n)

	// Go version

	/*
		h := sha1.New()
		h.Write([]byte(hello.PIN))
		pinHash := h.Sum(nil)
	*/
	pinHash := sha1.Sum([]byte(hello.PIN))
	fmt.Printf("PIN hash: %02x\n", pinHash)

	// Assertion
	if bytes.Compare(pinHash[:], dbgHexToBytes("7110eda4d09e062aa5e4a390b0a572ac0d2c0220")) != 0 {
		panic("invalid pinHash: " + hex.EncodeToString(pinHash[:]))
	}

	goKey := pinHash[:16]
	// Assertion
	if bytes.Compare(goKey, hello.Key) != 0 {
		panic("invalid key: " + hex.EncodeToString(goKey))
	}

	encrypted, err := aesEncryptCBC(hello.Key, publicKey)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("encrypted: %02x\n", encrypted)
	// Assertion
	if bytes.Compare(encrypted, dbgHexToBytes("ee866a1427e32c057ec3d5cbb0b227f61c9958f0b85685bfec8654ea964db04baea6af4e95b00b6cd22d0f15175ac48203ba4b1181a6b84204a44e4b81b57f4be024372402e59bbadedbdfed38d2e2231abc6a360d327e21d4dd0f6fa55c8a6004a30f0f44ca101966fc7d70585ff5bb77a34d3dc0528a5c476a916696183b80")) != 0 {
		panic("invalid encrypted")
	}

	swapped, err := aesEncryptECB(wbKey, encrypted)
	if err != nil {
		panic(err.Error()) // TODO remove panics
	}
	swapped = swapped[:128]
	fmt.Printf("swapped: %02x\n", swapped)

	// Assertion
	if bytes.Compare(swapped, dbgHexToBytes("c0dee54ed567f0310a5185dbcdcb0c3e8753b342409786699d343060ab8200afce6bb581e3b60779fe88f1b1bd7c39a0b14898b34f8dfa058e9d377e7050e97d51e18937f04a936b76e00cacbd95b4f5353d8a716b7ab76ec85fc0d3e75cd242e909698ed6f4ba8a3ea5ff33a232400d07cb659f496aa631b5df86253dece96a")) != 0 {
		panic("invalid swapped")
	}

	var dataBuf bytes.Buffer
	binary.Write(&dataBuf, binary.BigEndian, uint32(len(hello.UserID)))
	dataBuf.WriteString(hello.UserID)
	dataBuf.Write(swapped)

	dataHash := sha1.Sum(dataBuf.Bytes()) // ctx
	fmt.Printf("data hash: %02x\n", dataHash)

	// Assertion
	if bytes.Compare(dataHash[:], hello.Ctx) != 0 {
		panic("invalid swapped")
	}

	var serverHelloBuf bytes.Buffer

	// Header
	serverHelloBuf.Write([]byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Data Size
	fmt.Printf("DBG data len=%d\n", dataBuf.Len())
	binary.Write(&serverHelloBuf, binary.BigEndian, uint32(dataBuf.Len()))
	// Data
	serverHelloBuf.Write(dataBuf.Bytes())
	// Footer
	serverHelloBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})

	//fmt.Printf("expect hello: %02X\n", serverHelloBytes)
	fmt.Printf("server hello: %02X\n", serverHelloBuf.Bytes())

	// Assertion
	if bytes.Compare(serverHelloBuf.Bytes(), serverHelloBytes) != 0 {
		panic("invalid serverHello")
	}

	return serverHelloBuf.Bytes(), nil
}

// ParseClientHello parses the client message and checks it's valid
// Returns (SKPrime, ctx) and an error if it failed.
func ParseClientHello(hello HelloData, clientHello string) ([]byte, []byte, error) {
	data, err := hex.DecodeString(clientHello)
	if err != nil {
		return nil, nil, errors.New("could not decode ClientHello string")
	}

	cUserID := C.CString(hello.UserID)
	cHash := (*C.char)(unsafe.Pointer(&hello.Ctx[0]))
	cAESKey := (*C.char)(unsafe.Pointer(&hello.Key[0]))
	cClientHello := (*C.char)(unsafe.Pointer(&data[0]))

	//println("ClientHello:", clientHello)

	// "skprime" is (20B) long
	// "ctx" is (16B) long
	skprime := make([]byte, 32)
	ctx := make([]byte, 32)

	r := C.parseClientHello(cClientHello, (C.uint)(len(clientHello)/2),
		cHash, cAESKey, cUserID,
		(*C.char)(unsafe.Pointer(&skprime[0])),
		(*C.char)(unsafe.Pointer(&ctx[0])))
	// C.fflush(C.stdout) // for C debug messages

	// ### <Go version>

	const gxSize = 0x80

	// TODO check CH length looks acceptable --  >= 4[=int32]+128[=gx]+20[=sha]+len(userID)
	println("CH length:", len(data))

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
		// XXX Could not read len1
	}
	// TODO check length // len(userID)+132+sha(=20)
	println("len1: ", payloadSize)

	// data[11:15]
	if err := binary.Read(dataBuf, binary.BigEndian, &length); err != nil {
		return nil, nil, errors.New("could not read user-id len")
	}
	println("len2: ", length)
	if length+152 > payloadSize { // check uid len is reasonable
		return nil, nil, errors.New("invalid client ID length")
	}
	// XXX remove this check when done with debug prints
	if int(length) != len(hello.UserID) {
		println("client user-id length does not match our user-id")
	}

	clientUserID := make([]byte, length)
	if n, _ := dataBuf.Read(clientUserID); n != int(length) {
		panic("failed to read ClientHello's user-id")
	}
	println("client UserID:", string(clientUserID))

	if string(clientUserID) != hello.UserID {
		return nil, nil, fmt.Errorf("client user-id differs from ours: `%s`",
			string(clientUserID))
	}

	encWBGx := make([]byte, gxSize)
	if n, _ := dataBuf.Read(encWBGx); n != gxSize {
		panic("failed to read ClientHello's data")
	}
	fmt.Printf("encWBGx: %02x\n", encWBGx)

	// Assertion
	if bytes.Compare(encWBGx, dbgHexToBytes("4e71727c54c92ce0dd2d599883d27d2c819bb78f3cecea7703e155fa199988a7a50a2d647501c0d9e1c86acd272ac1da0099096d50bd1f13afedbe0bb4bc54ae9c6e2558e552ed544eb6e8837d4cbf2460b6c869956992d20e630bf31b0b36c20c318af2b9bc1e1ab3991e4d4e6bc13765353e89045ac627501a5761ebf8982d")) != 0 {
		panic("invalid encWBGx")
	}

	encGx, err := aesDecryptECB(wbKey, encWBGx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aesDecryptECB failed")
	}
	fmt.Printf("encGx: %02x\n", encGx)

	// Assertion
	if bytes.Compare(encGx, dbgHexToBytes("f10496fce6de3931b1596757acbf50048a677a0a5f217b728935b0399f4fbdabeb680ecb7164855c17375751458acef7979ca21afccaab70fe8a097761d7c4ef0299aa917b4893057db094019a202510f6403d8a13f0333141cce9f54906edd06e1b2ebea128c07037508e42ebed759df60e1524575618f64c55d697ef9fed93")) != 0 {
		panic("invalid encGx")
	}

	gx, err := aesDecryptCBC(hello.Key, encGx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "aesDecryptCBC failed")
	}
	fmt.Printf("gx: %02x\n", gx)

	// Assertion
	if bytes.Compare(gx, dbgHexToBytes("433a7096b894041d018dde0e75eb7e03ed6073c04ca0bd0733f4b767630effddf6c7411cb4662ab0796fb6bfcb16e449ed5a9ae7c63273ae2d4a10e7faea39cb52c96275f8813eed0cd2c1b20d24c32ff5377507728586a131b4226fbad91a1d01c78d994c9b993e02f9db19e0b7a1e47a509415deb1586e59fe88e7aa1abf0e")) != 0 {
		panic("invalid gx")
	}

	bnGx := new(big.Int)
	bnPrime := new(big.Int)
	bnPrivateKey := new(big.Int)
	bnSecret := new(big.Int)

	bnGx.SetBytes(gx)
	bnPrime.SetBytes(prime)
	bnPrivateKey.SetBytes(privateKey)
	bnSecret.Exp(bnGx, bnPrivateKey, bnPrime)

	secret := bnSecret.Bytes()
	fmt.Printf("secret: %02x\n", secret)

	// Assertion
	if bytes.Compare(secret, dbgHexToBytes("14e52221d2f0aa089e4c1552348cf74ee75e6d937093dbc5844461b6d97476c69202a58e61f5fc558af7a219c4abe80a0091eec692a6b039e3a180247a1f42e734064d864de0355b2ff0939813833a55c2f73ba893dc338f217b307e15e8d577077286ea081e2be782c90a2312e249b144a92a7697c8ef2225ff786f2b42779a")) != 0 {
		panic("invalid secret")
	}

	clientHash := make([]byte, 20)
	if n, _ := dataBuf.Read(clientHash); n != len(clientHash) {
		panic("failed to read ClientHello's hash")
	}
	fmt.Printf("client hash: %02x\n", clientHash)

	// Assertion
	if bytes.Compare(clientHash, dbgHexToBytes("d7be3cdca12d893aae18429fab01150a1274b56b")) != 0 {
		panic("invalid clientHash")
	}

	if flag, err := dataBuf.ReadByte(); err != nil {
		panic("failed to read ClientHello's flag #1")
	} else {
		fmt.Printf("client flag #1: %02x\n", flag) // DBG XXX
		if flag != 0 {
			return nil, nil, errors.New("Client Hello parsing failed: flag #1 is not null")
		}
	}

	// Flags
	var clientFlag2 uint32
	if err := binary.Read(dataBuf, binary.BigEndian, &clientFlag2); err != nil {
		panic("failed to read ClientHello's flag #2")
	}
	fmt.Printf("client flag #2: %02x\n", clientFlag2)
	if clientFlag2 != 0 {
		return nil, nil, errors.New("Client Hello parsing failed: flag #2 is not null")
	}

	// Hashes
	h := sha1.New()
	h.Write([]byte(hello.UserID))
	h.Write(secret)
	calculatedHash := h.Sum(nil)
	fmt.Printf("calculated hash #1: %02x\n", calculatedHash)

	// Assertion
	if bytes.Compare(calculatedHash, dbgHexToBytes("d7be3cdca12d893aae18429fab01150a1274b56b")) != 0 {
		return nil, nil, errors.New("bad calculatedHash")
	}

	// PIN is OK;
	// Compute key and hash

	h = sha1.New()
	h.Write([]byte(clientUserID)) // XXX can both differ?
	h.Write([]byte(hello.UserID)) // XXX
	h.Write(gx)
	h.Write(publicKey)
	h.Write(secret)
	calculatedHash = h.Sum(nil) // skprime  TODO rename XXX
	fmt.Printf("calculated hash #2 (skprime): %02x\n", calculatedHash)

	// Assertion
	if bytes.Compare(calculatedHash, skprime[:20]) != 0 {
		return nil, nil, errors.New("bad skprime")
	}

	skprimeHash := sha1.Sum(skprime[:21])
	fmt.Printf("skprimehash: %02x\n", skprimeHash)

	tmpCtx, err := applySamyGOKeyTransform(transKey, skprimeHash[:16])
	if err != nil {
		return nil, nil, errors.Wrap(err, "KeyTransform failed")
	}
	fmt.Printf("ctx: %02x\n", tmpCtx)
	fmt.Printf("exp: %02x\n", ctx)

	// Assertion
	if bytes.Compare(tmpCtx, ctx[:16]) != 0 {
		return nil, nil, errors.New("bad ctx")
	}

	// ### </Go version>

	if r != 0 {
		var msg string
		switch r {
		case C.ERR_SC_PIN:
			msg = "pin error"
		case C.ERR_SC_FIRST_FLAG:
			msg = "bad user id"
		case C.ERR_SC_BAD_USERID:
			msg = "first flag error"
		case C.ERR_SC_SECOND_FLAG:
			msg = "second flag error"
		case C.ERR_SC_BAD_CLIENTHELLO:
			msg = "suspicious ClientHello"
		default:
			msg = "unknown error"
		}

		return nil, nil, errors.New("Client Hello parsing failed: " + msg)
	}

	return skprime[:20], ctx[:16], nil
}

// GenerateServerAcknowledge builds the ServerAcknowledge data string
func GenerateServerAcknowledge(skprime []byte) (string, error) {
	skprime = append(skprime, '\x01')
	/*
		h := sha1.New()
		h.Write([]byte(skprime))
		bs := h.Sum(nil)
	*/
	bs := sha1.Sum([]byte(skprime))
	return "0103000000000000000014" + fmt.Sprintf("%X", bs) + "0000000000", nil
}

// ParseClientAcknowledge checks the ClientAcknowledge data
func ParseClientAcknowledge(clientAck string, skprime []byte) error {
	if len(clientAck) < 72 {
		return errors.New("incorrect client acknowledge length")
	}
	skprime = append(skprime, '\x02')
	/*
		h := sha1.New()
		h.Write([]byte(skprime))
		bs := h.Sum(nil)
	*/
	bs := sha1.Sum([]byte(skprime))
	expectedClientAckData := fmt.Sprintf("%X", bs) + "0000000000"

	if expectedClientAckData == clientAck[22:] {
		return nil
	}
	return errors.New("incorrect client acknowledge")
}

// *** XXX Debug
func dbgHexToBytes(s string) []byte {
	h, _ := hex.DecodeString(s)
	return h
}
