package password_storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/kostage/key_storage/internal/encrypt"
	"github.com/kostage/key_storage/internal/key"
	"github.com/kostage/key_storage/internal/types"
	"github.com/kostage/key_storage/internal/utils"
	"github.com/pkg/errors"
)

type PasswordRecord struct {
	Name      string `json:"name"`
	Password  string `json:"password"`
	Signature string `json:"signature"`
}

type PasswordStorage struct {
	Recovery  types.KeyRecoveryJson `json:"recover"`
	Passwords []*PasswordRecord     `json:"passwords"`
	Signature string                `json:"signature"`
}

func NewPasswordStorageFromFile(data []byte) (*PasswordStorage, error) {
	storage := &PasswordStorage{}
	err := json.Unmarshal(data, storage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal password storage")
	}
	return storage, nil
}

func NewPasswordStorageFromScratch(pass string, pin int) (*PasswordStorage, error) {
	recoveryData, err := generateRecoveryData(pass, pin)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create recovery data")
	}
	recoveryDataJson := recoveryDataFromHex(recoveryData)
	encryptor, err := NewEncryptorFromRecovery(pass, pin, recoveryDataJson)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create recovery data")
	}
	signature, err := createPasswordBlockSignature([]*PasswordRecord{}, encryptor)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create recovery data")
	}
	return &PasswordStorage{
		Recovery:  *recoveryDataJson,
		Passwords: make([]*PasswordRecord, 0),
		Signature: signature,
	}, nil
}

func (storage *PasswordStorage) DumpFile() ([]byte, error) {
	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal password storage")
	}
	return data, nil
}

func (storage *PasswordStorage) GetPassword(name string, encryptor *encrypt.Encryptor) (string, error) {
	record, err := findSorted(storage.Passwords, name)
	if err != nil {
		return "", fmt.Errorf("password [%s]  not found", name)
	}
	if err = validatePasswordSignature(record, encryptor); err != nil {
		return "", errors.Wrapf(err, "password [%s] signature invalid", name)
	}
	passwordEncr, err := utils.StrToHex(record.Password)
	if err != nil {
		return "", errors.Wrap(err, "not a hex password string")
	}
	password, err := encryptor.Decrypt(passwordEncr)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt password")
	}
	return string(password), nil
}

func (storage *PasswordStorage) DeletePassword(name string, encryptor *encrypt.Encryptor) error {
	var err error
	if storage.Passwords, err = deleteSorted(storage.Passwords, name); err != nil {
		return errors.Wrap(err, "failed to delete password")
	}
	signature, err := createPasswordBlockSignature(storage.Passwords, encryptor)
	if err != nil {
		return errors.Wrap(err, "failed to sign password")
	}
	storage.Signature = signature
	return nil
}

func (storage *PasswordStorage) AddPassword(name, password string, encryptor *encrypt.Encryptor) error {
	encrPass, err := encryptor.Encrypt([]byte(password))
	if err != nil {
		return errors.Wrap(err, "failed to encrypt password")
	}
	newRec := &PasswordRecord{
		Name:     name,
		Password: utils.HexToStr(encrPass),
	}
	if newRec.Signature, err = createPasswordSignature(newRec, encryptor); err != nil {
		return errors.Wrap(err, "failed to sign password")
	}
	if storage.Passwords, err = insertSorted(storage.Passwords, newRec); err != nil {
		return errors.Wrapf(err, "failed to add password [%s]", name)
	}
	if storage.Signature, err = createPasswordBlockSignature(storage.Passwords, encryptor); err != nil {
		return errors.Wrap(err, "failed to sign password block")
	}
	return nil
}

func (storage *PasswordStorage) ChangePassword(name, password string, encryptor *encrypt.Encryptor) error {
	record, err := findSorted(storage.Passwords, name)
	if err != nil {
		return fmt.Errorf("password not found")
	}
	encrPass, err := encryptor.Encrypt([]byte(password))
	if err != nil {
		return errors.Wrap(err, "failed to encrypt password")
	}
	record.Password = utils.HexToStr(encrPass)
	if record.Signature, err = createPasswordSignature(record, encryptor); err != nil {
		return errors.Wrap(err, "failed to sign password")
	}
	if storage.Signature, err = createPasswordBlockSignature(storage.Passwords, encryptor); err != nil {
		return errors.Wrap(err, "failed to sign password block")
	}
	return nil
}

func (storage *PasswordStorage) ValidatePasswordBlock(
	encryptor *encrypt.Encryptor,
) error {
	encrHash, err := utils.StrToHex(storage.Signature)
	if err != nil {
		return errors.Wrap(err, "failed to parse signature")
	}
	hash, err := encryptor.Decrypt(encrHash)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt signature")
	}
	hasher := sha256.New()
	for _, record := range storage.Passwords {
		_, err := hasher.Write([]byte(record.Name))
		if err != nil {
			return errors.Wrap(err, "failed to hash passwords block signature")
		}
		_, err = hasher.Write([]byte(record.Password))
		if err != nil {
			return errors.Wrap(err, "failed to hash passwords block signature")
		}
		_, err = hasher.Write([]byte(record.Signature))
		if err != nil {
			return errors.Wrap(err, "failed to hash passwords block signature")
		}
	}
	if !bytes.Equal(hash, hasher.Sum(nil)) {
		return fmt.Errorf("password map signature corrupt")
	}
	return nil
}

func generateRecoveryData(pass string, pin int) (*types.KeyRecoveryData, error) {
	keygen, err := key.NewKeyGenerator()
	if err != nil {
		return nil, err
	}
	recoveryData, err := keygen.Generate(pass, pin)
	if err != nil {
		return nil, err
	}
	return recoveryData, nil
}

func createPasswordSignature(
	record *PasswordRecord, encryptor *encrypt.Encryptor,
) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(record.Name))
	if err != nil {
		return "", errors.Wrap(err, "failed to hash password signature")
	}
	_, err = hasher.Write([]byte(record.Password))
	if err != nil {
		return "", errors.Wrap(err, "failed to hash password signature")
	}
	encrHash, err := encryptor.Encrypt(hasher.Sum(nil))
	if err != nil {
		return "", errors.Wrap(err, "failed to sign password")
	}
	return utils.HexToStr(encrHash), nil
}

func createPasswordBlockSignature(
	passwords []*PasswordRecord,
	encryptor *encrypt.Encryptor,
) (string, error) {
	hasher := sha256.New()
	for _, record := range passwords {
		_, err := hasher.Write([]byte(record.Name))
		if err != nil {
			return "", errors.Wrap(err, "failed to hash password name")
		}
		_, err = hasher.Write([]byte(record.Password))
		if err != nil {
			return "", errors.Wrap(err, "failed to hash password value")
		}
		_, err = hasher.Write([]byte(record.Signature))
		if err != nil {
			return "", errors.Wrap(err, "failed to hash password signature")
		}
	}
	encrHash, err := encryptor.Encrypt(hasher.Sum(nil))
	if err != nil {
		return "", errors.Wrap(err, "failed to sign password")
	}
	return utils.HexToStr(encrHash), nil
}

func validatePasswordSignature(
	record *PasswordRecord, encryptor *encrypt.Encryptor,
) error {
	encrHash, err := utils.StrToHex(record.Signature)
	if err != nil {
		return errors.Wrap(err, "not a hex signature string")
	}
	hash, err := encryptor.Decrypt(encrHash)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt signature")
	}
	hasher := sha256.New()
	_, err = hasher.Write([]byte(record.Name))
	if err != nil {
		return errors.Wrap(err, "failed to hash password name")
	}
	_, err = hasher.Write([]byte(record.Password))
	if err != nil {
		return errors.Wrap(err, "failed to hash password string")
	}
	if !bytes.Equal(hash, hasher.Sum(nil)) {
		return fmt.Errorf("password signature corrupt")
	}
	return nil
}

func NewEncryptorFromRecovery(
	passphrase string, pin int, recovery *types.KeyRecoveryJson,
) (*encrypt.Encryptor, error) {
	recoveryData, err := recoverDataFromStr(recovery)
	if err != nil {
		return nil, errors.Wrap(err, "invalid recovery json data")
	}
	keygen, _ := key.NewKeyGenerator()
	aesKey, err := keygen.Recover(passphrase, pin, recoveryData)
	if err != nil {
		return nil, errors.Wrap(err, "key recovery failed")
	}
	encryptor, err := encrypt.NewEncryptor(aesKey)
	if err != nil {
		return nil, errors.Wrap(err, "key recovery failed")
	}
	return encryptor, nil
}

func recoverDataFromStr(strData *types.KeyRecoveryJson) (*types.KeyRecoveryData, error) {
	k1, err := utils.StrToHex(strData.K1Encr)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse k1 hex")
	}
	k3, err := utils.StrToHex(strData.K3)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse k3 hex")
	}
	s, err := utils.StrToHex(strData.S)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse s hex")
	}
	return &types.KeyRecoveryData{
		K1Encr: k1,
		K3:     k3,
		S:      s,
	}, nil
}

func recoveryDataFromHex(hexData *types.KeyRecoveryData) *types.KeyRecoveryJson {
	return &types.KeyRecoveryJson{
		K1Encr: utils.HexToStr(hexData.K1Encr),
		K3:     utils.HexToStr(hexData.K3),
		S:      utils.HexToStr(hexData.S),
	}
}
