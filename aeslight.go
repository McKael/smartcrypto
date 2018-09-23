/*
	AES_128_Transform
	Based on code from rijndael-alg-fst (see below and aeslight.c.source),
	transpiled by c2go version: v0.25.2 Dubnium 2018-06-29

	If you have found any issues, please raise an issue at:
	https://github.com/elliotchance/c2go/
*/

package smartcrypto

import (
	"unsafe"
)

type u8 uint8
type u32 uint32

var rcon = []u32{
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000,
	// for 128-bit blocks, Rijndael never uses more than 10 rcon values
}

/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

func getu32(data *u8) u32 {
	return u32(u8(*(data)))<<24 ^
		u32(u8(*((*u8)(unsafe.Pointer(uintptr(unsafe.Pointer((data))) + 1)))))<<16 ^
		u32(u8(*((*u8)(unsafe.Pointer(uintptr(unsafe.Pointer((data))) + 2)))))<<8 ^
		u32(u8(*((*u8)(unsafe.Pointer(uintptr(unsafe.Pointer((data))) + 3)))))
}

func putu32(data *u8, n u32) {
	*(data) = u8(n >> 24)
	*((*u8)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + 1))) = u8(n >> 16)
	*((*u8)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + 2))) = u8(n >> 8)
	*((*u8)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + 3))) = u8(n)
}

/**
 * Expand the cipher key into the encryption key schedule.
 * Code transpiled by c2go, and cleaned up (Mikael).
 *
 * @return	the number of rounds for the given cipher key size.
 */
func rijndaelKeySetupEncTransform(nr int, rk *u32, cipherKey *u8) int {
	var temp u32
	var pData unsafe.Pointer

	//rk[0] = GETU32(cipherKey     );
	*rk = getu32(cipherKey)

	//rk[1] = GETU32(cipherKey +  4);
	pData = unsafe.Pointer(uintptr(unsafe.Pointer(cipherKey)) + 1*4)
	*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 1*4))) = getu32((*u8)(pData))

	//rk[2] = GETU32(cipherKey +  8);
	pData = unsafe.Pointer(uintptr(unsafe.Pointer(cipherKey)) + 2*4)
	*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 2*4))) = getu32((*u8)(pData))

	//rk[3] = GETU32(cipherKey + 12);
	pData = unsafe.Pointer(uintptr(unsafe.Pointer(cipherKey)) + 3*4)
	*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 3*4))) = getu32((*u8)(pData))

	pTe4 := &te4[0]
	pRcon := &rcon[0]
	i := 0
	for {
		temp = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 3*4)))
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 4*4))) = *rk ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(pTe4)) + (uintptr)(int32(temp>>16&0xff))*4)))&u32(0xff000000) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(pTe4)) + (uintptr)(int32(temp>>8&0xff))*4)))&u32(0xff0000) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(pTe4)) + (uintptr)(int32(temp&0xff))*4)))&u32(0xff00) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(pTe4)) + (uintptr)(int32(temp>>24))*4)))&u32(0xff) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(pRcon)) + (uintptr)(i)*4)))

		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 5*4))) = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 1*4))) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 4*4)))
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 6*4))) = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 2*4))) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 5*4)))
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 7*4))) = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 3*4))) ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 6*4)))

		i++
		if i == nr {
			return nr
		}
		rk = ((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + (uintptr)(4*4))))
	}
}

/*
 * Code transpiled by c2go, and cleaned up (Mikael).
 * Modified, usable for nr = 3 only.
 */
func rijndaelEncrypt3(rk *u32, pt *u8, ct *u8) {
	const nr = 3
	var s0 u32
	var s1 u32
	var s2 u32
	var s3 u32
	var t0 u32
	var t1 u32
	var t2 u32
	var t3 u32
	var pData unsafe.Pointer

	// Init
	// s0 = GETU32(pt     ) ^ rk[0];
	s0 = getu32(pt) ^ *rk
	// s1 = GETU32(pt +  4) ^ rk[1];
	pData = unsafe.Pointer(uintptr(unsafe.Pointer(pt)) + 1*4)
	s1 = getu32((*u8)(pData)) ^ *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 1*4)))
	// s2 = GETU32(pt +  8) ^ rk[2];
	pData = unsafe.Pointer(uintptr(unsafe.Pointer(pt)) + 2*4)
	s2 = getu32((*u8)(pData)) ^ *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 2*4)))
	// s3 = GETU32(pt + 12) ^ rk[3];
	pData = unsafe.Pointer(uintptr(unsafe.Pointer(pt)) + 3*4)
	s3 = getu32((*u8)(pData)) ^ *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 3*4)))

	// Round 1
	t0 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((s0>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((s1>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((s2>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((s3 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 4*4)))

	t1 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((s1>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((s2>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((s3>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((s0 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 5*4)))

	t2 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((s2>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((s3>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((s0>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((s1 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 6*4)))

	t3 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((s3>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((s0>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((s1>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((s2 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 7*4)))

	// Round 2
	s0 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((t0>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((t1>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((t2>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((t3 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 8*4)))

	s1 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((t1>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((t2>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((t3>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((t0 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 9*4)))

	s2 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((t2>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((t3>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((t0>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((t1 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 10*4)))

	s3 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te0[0])) + (uintptr)((t3>>24)*4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te1[0])) + (uintptr((t0>>16)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te2[0])) + (uintptr((t1>>8)&0xff) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te3[0])) + (uintptr((t2 & 0xff)) * 4)))) ^
		*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 11*4)))

	rk = ((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + (uintptr)(nr<<2)*4)))

	if nr == 3 { // (always)
		var pCt *u8

		// Round 3
		t0 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s0>>24)*4))))&0xff000000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s1>>16)&0xff)*4))))&0xff0000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s2>>8)&0xff)*4))))&0xff00 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s3&0xff)*4))))&0xff ^
			*rk
		putu32(ct, t0)

		t1 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s1>>24)*4))))&0xff000000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s2>>16)&0xff)*4))))&0xff0000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s3>>8)&0xff)*4))))&0xff00 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s0&0xff)*4))))&0xff ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 1*4)))
		pCt = (*u8)(unsafe.Pointer(uintptr(unsafe.Pointer(ct)) + 1*4))
		putu32(pCt, t1)

		t2 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s2>>24)*4))))&0xff000000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s3>>16)&0xff)*4))))&0xff0000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s0>>8)&0xff)*4))))&0xff00 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s1&0xff)*4))))&0xff ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 2*4)))
		pCt = (*u8)(unsafe.Pointer(uintptr(unsafe.Pointer(ct)) + 2*4))
		putu32(pCt, t2)

		t3 = *((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s3>>24)*4))))&0xff000000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s0>>16)&0xff)*4))))&0xff0000 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)(((s1>>8)&0xff)*4))))&0xff00 ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(&te4[0])) + (uintptr)((s2&0xff)*4))))&0xff ^
			*((*u32)(unsafe.Pointer(uintptr(unsafe.Pointer(rk)) + 3*4)))
		pCt = (*u8)(unsafe.Pointer(uintptr(unsafe.Pointer(ct)) + 3*4))
		putu32(pCt, t3)
	}
}

func aes128transform(nr int, key *uint8, plainText *uint8, cipherText *uint8) {
	const aes128rounds = 10

	rk := make([]u32, 4*(aes128rounds+1))
	rijndaelKeySetupEncTransform(nr, &rk[0], (*u8)(unsafe.Pointer(key)))
	rijndaelEncrypt3(&rk[0], (*u8)(unsafe.Pointer(plainText)), (*u8)(unsafe.Pointer(cipherText)))

	for i := range rk {
		rk[i] = 0
	}
}
