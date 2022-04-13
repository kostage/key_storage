package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHexToStrToHex(t *testing.T) {
	hex, err := StrToHex("48656c6c6f20476f7068657221")
	assert.NoError(t, err)
	str := HexToStr(hex)
	assert.Equal(t, "48656c6c6f20476f7068657221", str)
}
