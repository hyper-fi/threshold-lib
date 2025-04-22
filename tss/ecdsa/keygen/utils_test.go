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
