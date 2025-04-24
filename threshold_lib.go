package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"github.com/okx/threshold-lib/tss/ecdsa/keygen"
	"github.com/okx/threshold-lib/tss/ecdsa/sign"
	"github.com/okx/threshold-lib/tss/key/reshare"
)

//export EcdsaKeyGen
func EcdsaKeyGen() []string {
	return keygen.NewEcdsaKeyGen()
}

//export EcdsaRefresh
func EcdsaRefresh(share1st string, share2nd string) ([]string, error) {
	return reshare.RefreshEcdsaKeyShares(share1st, share2nd)
}

//export EcdsaDerivedPubKey
func EcdsaDerivedPubKey(share1st string, share2nd string, childIdx uint32) (string, error) {
	return sign.GetEcdsaDerivedPubKey(share1st, share2nd, childIdx)
}

//export EcdsaSign
func EcdsaSign(share1st string, share2nd string, childIdx uint32, signMessageHash []byte) (string, string, error) {
	return sign.EcdsaSign(share1st, share2nd, childIdx, signMessageHash)
}

func main() {}
