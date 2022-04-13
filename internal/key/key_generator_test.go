package key

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyGeneration(t *testing.T) {
	keyGenerator, _ := NewKeyGenerator()
	recovery, err := keyGenerator.Generate("password", 1111)
	assert.NoError(t, err)
	assert.NotNil(t, recovery)
}

func TestKeyRecovery(t *testing.T) {
	keyGenerator, _ := NewKeyGenerator()
	recovery, err := keyGenerator.Generate("password", 1111)
	assert.NoError(t, err)
	assert.NotNil(t, recovery)

	key, err := keyGenerator.Recover("password", 1111, recovery)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, aes.BlockSize, len(key))
}
