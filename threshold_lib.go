package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/hex"
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/ecdsa/sign"
	"github.com/okx/threshold-lib/tss/key/reshare"
	"runtime"
	"unsafe"
)

type ErrString string

//export FreeCString
func FreeCString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func EcdsaKeyGen() []string {
	return keygen.NewEcdsaKeyGen()
}

//export EcdsaKeyGenSimple
func EcdsaKeyGenSimple() (*C.char, *C.char, *C.char) {
	shares := keygen.NewEcdsaKeyGen()
	share0, share1, share2 := shares[0], shares[1], shares[2]

	var p0, p1, p2 runtime.Pinner
	p0.Pin(unsafe.Pointer(&share0))
	p1.Pin(unsafe.Pointer(&share1))
	p2.Pin(unsafe.Pointer(&share2))

	defer p0.Unpin()
	defer p1.Unpin()
	defer p2.Unpin()

	return C.CString(share0), C.CString(share1), C.CString(share2)
}

func EcdsaRefresh(share1st string, share2nd string) ([]string, error) {
	return reshare.RefreshEcdsaKeyShares(share1st, share2nd)
}

//export EcdsaRefreshSimple
func EcdsaRefreshSimple(share1st string, share2nd string) (string, string, string, ErrString) {
	shares, err := reshare.RefreshEcdsaKeyShares(share1st, share2nd)
	if err != nil {
		return "", "", "", ErrString(err.Error())
	} else {
		return shares[0], shares[1], shares[2], ""
	}
}

func EcdsaDerivedPubKey(share1st string, share2nd string, childIdx uint32) (string, error) {
	return sign.GetEcdsaDerivedPubKey(share1st, share2nd, childIdx)
}

//export EcdsaDerivedPubKeySimple
func EcdsaDerivedPubKeySimple(share1st string, share2nd string, childIdx uint32) (string, ErrString) {
	pub, err := sign.GetEcdsaDerivedPubKey(share1st, share2nd, childIdx)
	if err != nil {
		return "", ErrString(err.Error())
	} else {
		return pub, ""
	}
}

func EcdsaSign(share1st string, share2nd string, childIdx uint32, signMessageHash []byte) (string, string, error) {
	return sign.EcdsaSign(share1st, share2nd, childIdx, signMessageHash)
}

//export EcdsaSignSimple
func EcdsaSignSimple(share1st string, share2nd string, childIdx uint32, signMessageHashHex string) (string, string, ErrString) {
	signMessageHash, err := hex.DecodeString(signMessageHashHex)
	if err != nil {
		return "", "", ErrString(err.Error())
	}
	r, s, err := sign.EcdsaSign(share1st, share2nd, childIdx, signMessageHash)
	if err != nil {
		return "", "", ErrString(err.Error())
	}
	return r, s, ""
}

func main() {}
