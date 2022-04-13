package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type Encryptor struct {
	cipherBlock cipher.Block
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Encryptor{cipherBlock: cipherBlock}, nil
}

func (encryptor *Encryptor) Encrypt(data []byte) ([]byte, error) {
	cipherData := make([]byte, aes.BlockSize+len(data))
	iv := cipherData[:encryptor.cipherBlock.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(encryptor.cipherBlock, iv)
	stream.XORKeyStream(cipherData[aes.BlockSize:], data)
	return cipherData, nil
}

func (encryptor *Encryptor) Decrypt(cipherData []byte) ([]byte, error) {
	if len(cipherData) < aes.BlockSize {
		return nil, fmt.Errorf("text is too short")
	}
	iv := cipherData[:encryptor.cipherBlock.BlockSize()]
	cipherData = cipherData[encryptor.cipherBlock.BlockSize():]

	stream := cipher.NewCFBDecrypter(encryptor.cipherBlock, iv)
	stream.XORKeyStream(cipherData, cipherData)
	return cipherData, nil
}
