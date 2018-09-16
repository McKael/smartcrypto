package smartcrypto

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lssl -lcrypto
// #include <stdio.h> // for fflush
// #include <stdlib.h>
// #include "crypto.h"
import "C"
import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

// HelloData contains data to generate the ServerHello and check the ClientHello
type HelloData struct {
	UserID, PIN string
	Key         []byte
	Ctx         []byte
}

// GenerateServerHello builds the Server Hello hex string
func GenerateServerHello(hello *HelloData) ([]byte, error) {
	cUserID := C.CString(hello.UserID)
	cPin := C.CString(hello.PIN)

	if len(hello.UserID) < 1 || len(hello.UserID) > 96 {
		// Arbitrary length check
		return nil, errors.New("invalid UserID size")
	}

	expectedLength := 10 + 1 + (4 + len(hello.UserID) + 128) + 5
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
	if hl != expectedLength {
		return nil, errors.New("unexpected Hello length")
	}

	hello.Key = key
	hello.Ctx = ctx

	return C.GoBytes(unsafe.Pointer(serverHello), n), nil
}

// ParseClientHello parses the client message and checks it's valid
// Returns (SKPrime, ctx) and an error if it failed.
func ParseClientHello(hello HelloData, clientHello string) ([]byte, []byte, error) {
	rawClientHello, err := hex.DecodeString(clientHello)
	if err != nil {
		return nil, nil, errors.New("could not decode ClientHello string")
	}

	cUserID := C.CString(hello.UserID)
	cHash := (*C.char)(unsafe.Pointer(&hello.Ctx[0]))
	cAESKey := (*C.char)(unsafe.Pointer(&hello.Key[0]))
	cClientHello := (*C.char)(unsafe.Pointer(&rawClientHello[0]))

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
	h := sha1.New()
	h.Write([]byte(skprime))
	bs := h.Sum(nil)
	return "0103000000000000000014" + fmt.Sprintf("%X", bs) + "0000000000", nil
}

// ParseClientAcknowledge checks the ClientAcknowledge data
func ParseClientAcknowledge(clientAck string, skprime []byte) error {
	if len(clientAck) < 72 {
		return errors.New("incorrect client acknowledge length")
	}
	skprime = append(skprime, '\x02')
	h := sha1.New()
	h.Write([]byte(skprime))
	bs := h.Sum(nil)
	expectedClientAckData := fmt.Sprintf("%X", bs) + "0000000000"

	if expectedClientAckData == clientAck[22:] {
		return nil
	}
	return errors.New("incorrect client acknowledge")
}
