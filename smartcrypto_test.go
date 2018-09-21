package smartcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hexToBytes(s string) []byte {
	h, _ := hex.DecodeString(s)
	return h
}

func TestGenerateServerHello(t *testing.T) {
	hd := HelloData{UserID: "654321", PIN: "1234"}
	expected := HelloData{
		Key: hexToBytes("7110eda4d09e062aa5e4a390b0a572ac"),
		Ctx: hexToBytes("63616c1be9bf978af9941d2ee880360b1ff4c376"),
	}
	expectedServerHello := hexToBytes("010200000000000000008A00000006363534333231C0DEE54ED567F0310A5185DBCDCB0C3E8753B342409786699D343060AB8200AFCE6BB581E3B60779FE88F1B1BD7C39A0B14898B34F8DFA058E9D377E7050E97D51E18937F04A936B76E00CACBD95B4F5353D8A716B7AB76EC85FC0D3E75CD242E909698ED6F4BA8A3EA5FF33A232400D07CB659F496AA631B5DF86253DECE96A0000000000")

	serverHello, err := GenerateServerHello(&hd)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(hd.Key, expected.Key) != 0 {
		t.Error("AES key mismatch")
	}
	if bytes.Compare(hd.Ctx, expected.Ctx) != 0 {
		t.Error("hash mismatch")
	}
	if bytes.Compare(serverHello, expectedServerHello) != 0 {
		t.Error("bad ServerHello")
	}
}

func TestParseClientHello(t *testing.T) {
	hd := HelloData{
		UserID: "654321",
		PIN:    "4432",
		Key:    hexToBytes("0c08e787853fcfccc69614c4cfb4059e"),
		Ctx:    hexToBytes("aa91080efb5d12339ef3c30b7373358b7f6e1342"),
	}
	clientHello := "010100000000000000009E000000063635343332314E71727C54C92CE0DD2D599883D27D2C819BB78F3CECEA7703E155FA199988A7A50A2D647501C0D9E1C86ACD272AC1DA0099096D50BD1F13AFEDBE0BB4BC54AE9C6E2558E552ED544EB6E8837D4CBF2460B6C869956992D20E630BF31B0B36C20C318AF2B9BC1E1AB3991E4D4E6BC13765353E89045AC627501A5761EBF8982DD7BE3CDCA12D893AAE18429FAB01150A1274B56B0000000000"
	expectedSKPrime := hexToBytes("0817b063a0609dd37285c0d188a9e347f6ede809")
	expectedCtx := hexToBytes("0dc8ef22369da598815f5fa40eb174a9")

	skprime, ctx, err := ParseClientHello(hd, clientHello)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(skprime, expectedSKPrime) != 0 {
		t.Error("skprime mismatch")
	}
	if bytes.Compare(ctx, expectedCtx) != 0 {
		t.Error("ctx mismatch")
	}
}

func TestGenerateServerAcknowledge(t *testing.T) {
	skprime := hexToBytes("c28727fe3c9f81a4db9b335a08e75b8a1b817652")
	expectedAck := "0103000000000000000014A415F89EF3EAA64F34F06A1A908CA9B75358034A0000000000"
	s, err := GenerateServerAcknowledge(skprime)
	if err != nil {
		t.Fatal(err)
	}
	if s != expectedAck {
		t.Error("bad server acknowledge")
	}
}

func TestParseClientAcknowledge(t *testing.T) {
	var clientAckTests = []struct {
		clientAck string
		skprime   []byte
		success   bool
	}{
		{
			"01040000000000000000144B5B9260A1372B211EE9DE07531D5E1D967ECE320000000000",
			hexToBytes("0817b063a0609dd37285c0d188a9e347f6ede809"),
			true,
		},
		{
			"010400000000000000001409A8CA739EF03F47C883B0A2D1BF701FB9EE52910000000000",
			hexToBytes("c28727fe3c9f81a4db9b335a08e75b8a1b817652"),
			true,
		},
		{
			"010400000000000000001409A8CA739EF03F47C883B0A2D1BF701FB9EE5291000000001",
			hexToBytes("c28727fe3c9f81a4db9b335a08e75b8a1b817652"),
			false,
		},
		{
			"010400000000000000001409A8CA739EF03F47C883B0A2D1BF701FB9FF56660000000000",
			hexToBytes("c28727fe3c9f81a4db9b335a08e75b8a1b817652"),
			false,
		},
	}

	for i, tt := range clientAckTests {
		var e bool
		if err := ParseClientAcknowledge(tt.clientAck, tt.skprime); err != nil {
			e = true
		}
		if e == tt.success {
			t.Errorf("test %d failed: expected success=%v, got error=%v", i+1, tt.success, e)
		}
	}
}
