package key

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/kostage/key_storage/internal/encrypt"
	"github.com/kostage/key_storage/internal/types"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	k1ByteLen = aes.BlockSize
	ivByteLen = aes.BlockSize
	sByteLen  = aes.BlockSize / 2
)

type KeyGenerator struct {
}

func (generator *KeyGenerator) Recover(passphrase string, pin int, recovData *types.KeyRecoveryData) ([]byte, error) {
	key := pbkdf2.Key([]byte(passphrase), recovData.S, pin, aes.BlockSize*2, sha256.New)
	k2, k3 := key[:k1ByteLen], key[k1ByteLen:]
	if !bytes.Equal(k3, recovData.K3) {
		return nil, fmt.Errorf("k3 has been changed")
	}
	encryptor, err := encrypt.NewEncryptor(k2)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create encryptor")
	}
	k1, err := encryptor.Decrypt(recovData.K1Encr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt k1")
	}
	return k1, nil
}

func (generator *KeyGenerator) Generate(passphrase string, pin int) (*types.KeyRecoveryData, error) {
	k1 := make([]byte, k1ByteLen)
	s := make([]byte, sByteLen)
	rand.Read(k1)
	rand.Read(s)
	key := pbkdf2.Key([]byte(passphrase), s, pin, aes.BlockSize*2, sha256.New)
	k2, k3 := key[:k1ByteLen], key[k1ByteLen:]
	encryptor, err := encrypt.NewEncryptor(k2)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create encryptor")
	}
	k1Encr, err := encryptor.Encrypt(k1)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt k1")
	}
	return &types.KeyRecoveryData{
		K1Encr: k1Encr,
		K3:     k3,
		S:      s,
	}, nil
}

func NewKeyGenerator() (*KeyGenerator, error) {
	return &KeyGenerator{}, nil
}
