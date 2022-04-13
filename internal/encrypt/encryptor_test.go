package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func encryptDecript(encryptor *Encryptor, data []byte) ([]byte, error) {
	encrypted, err := encryptor.Encrypt(data)
	if err != nil {
		return nil, err
	}
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func TestEncryptor(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	rand.Read(key)
	encryptor, err := NewEncryptor(key)
	assert.NoError(t, err)
	assert.NotNil(t, encryptor)

	dummyData := []byte("dummy string")
	result, err := encryptDecript(encryptor, dummyData)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(dummyData, result))

	// test when empty
	dummyData = []byte("")
	result, err = encryptDecript(encryptor, dummyData)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(dummyData, result))

}
