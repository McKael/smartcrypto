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
	fmt.Printf("PIN hash: %02x\n", pinHash)

	// Assertion
	if bytes.Compare(pinHash[:], dbgHexToBytes("7110eda4d09e062aa5e4a390b0a572ac0d2c0220")) != 0 {
		panic("invalid pinHash: " + hex.EncodeToString(pinHash[:]))
	}

	hello.Key = pinHash[:16]
	/*
		// Assertion
		if bytes.Compare(hello.Key, ...) != 0 {
			panic("invalid key: " + hex.EncodeToString(hello.Key))
		}
	*/

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
		return nil, errors.Wrap(err, "aesEncryptECB failed")
	}
	swapped = swapped[:128]
	fmt.Printf("swapped: %02x\n", swapped)

	// Assertion
	if bytes.Compare(swapped, dbgHexToBytes("c0dee54ed567f0310a5185dbcdcb0c3e8753b342409786699d343060ab8200afce6bb581e3b60779fe88f1b1bd7c39a0b14898b34f8dfa058e9d377e7050e97d51e18937f04a936b76e00cacbd95b4f5353d8a716b7ab76ec85fc0d3e75cd242e909698ed6f4ba8a3ea5ff33a232400d07cb659f496aa631b5df86253dece96a")) != 0 {
		panic("invalid swapped")
	}

	// Compute ctx
	var dataBuf bytes.Buffer
	binary.Write(&dataBuf, binary.BigEndian, uint32(len(hello.UserID)))
	dataBuf.WriteString(hello.UserID)
	dataBuf.Write(swapped)

	dataHash := sha1.Sum(dataBuf.Bytes()) // ctx
	hello.Ctx = dataHash[:]

	fmt.Printf("data hash (ctx): %02x\n", dataHash)

	/*
		// Assertion
		if bytes.Compare(hello.Ctx, ...) != 0 {
			panic("invalid swapped")
		}
	*/

	// dataBuf will contain the ServerHello bytes
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

	/*
		// Assertion
		if bytes.Compare(serverHelloBuf.Bytes(), serverHelloBytes) != 0 {
			panic("invalid serverHello")
		}
	*/

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

	// TODO check CH length looks acceptable --  >= 4[=int32]+128[=gx]+20[=sha]+len(userID)
	// Not sure the userID length should be used though
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
	// TODO check length // len(userID)+132+sha(=20)  (not sure 'bout userID)
	println("len1: ", payloadSize)

	// data[11:15]
	if err := binary.Read(dataBuf, binary.BigEndian, &length); err != nil {
		return nil, nil, errors.New("could not read user-id len")
	}
	println("len2: ", length)
	if length+152 > payloadSize { // check uid len is reasonable
		return nil, nil, errors.New("invalid client ID length")
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

	// Flags
	if flag, err := dataBuf.ReadByte(); err != nil {
		panic("failed to read ClientHello's flag #1")
	} else {
		fmt.Printf("client flag #1: %02x\n", flag) // DBG XXX
		if flag != 0 {
			return nil, nil, errors.New("Client Hello parsing failed: flag #1 is not null")
		}
	}

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
	skprime := calculatedHash[:]
	fmt.Printf("calculated hash #2 (skprime): %02x\n", skprime)

	// Assertion
	if bytes.Compare(skprime, dbgHexToBytes("0817b063a0609dd37285c0d188a9e347f6ede809")) != 0 {
		return nil, nil, errors.New("bad skprime")
	}

	skprimeHash := sha1.Sum(skprime[:21])
	fmt.Printf("skprimehash: %02x\n", skprimeHash)

	fmt.Printf("transKey: %02x\n", transKey)

	ctx, err := keyTransform(transKey, skprimeHash[:16])
	if err != nil {
		return nil, nil, errors.Wrap(err, "KeyTransform failed")
	}
	fmt.Printf("ctx: %02x\n", ctx)

	// XXX ctx = ctx[:16]  // ???

	return skprime, ctx, nil
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
