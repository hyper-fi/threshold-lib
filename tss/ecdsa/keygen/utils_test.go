package keygen

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewPaillierKey(t *testing.T) {
	pKey, err := NewPaillierKey()
	require.NoError(t, err)
	fmt.Println(pKey)
}

func TestMarshalPaillierKey(t *testing.T) {
	pKey, err := NewPaillierKey()
	require.NoError(t, err)
	bs, err := MarshalPaillierKey(pKey)
	require.NoError(t, err)
	fmt.Println(string(bs))
	pKey2, err := UnMarshalToPaillierKey(bs)
	require.NoError(t, err)
	fmt.Println(pKey2)
}

func TestNewPreParamsWithDlnProof(t *testing.T) {
	proof := NewPreParamsWithDlnProof()
	fmt.Println(proof.Params.NTildei.String())
	fmt.Println(proof.Params.H1i.String())
	fmt.Println(proof.Params.H2i.String())
	fmt.Println(proof.Params.Alpha.String())
	fmt.Println(proof.Params.Beta.String())
	fmt.Println(proof.Params.P.String())
	fmt.Println(proof.Params.Q.String())
}

func TestMarshalPreParamsWithDlnProof(t *testing.T) {
	proof := NewPreParamsWithDlnProof()
	bs, err := MarshalPreParamsWithDlnProof(proof)
	require.NoError(t, err)
	fmt.Println(string(bs))
	proof2, err := UnMarshalPreParamsWithDlnProof(bs)
	require.NoError(t, err)
	fmt.Println(proof2)
}
