package utils

import "encoding/hex"

func HexToStr(src []byte) string {
	return hex.EncodeToString(src)
}

func StrToHex(str string) ([]byte, error) {
	return hex.DecodeString(str)
}
