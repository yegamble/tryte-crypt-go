package tryte_cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
	"golang.org/x/crypto/scrypt"
)

type TryteEncryptor interface{}

type ScryptOptions struct {
	N      int
	R      int
	P      int
	KeyLen int
}

func toughnessSetting(n int) (string, error) {

	if n == 16384 {
		return "", nil
	}

	if n == 32768 {
		return ":T1", nil
	}

	if n == 65536 {
		return ":T2", nil
	}

	if n == 131072 {
		return ":T3", nil
	}

	if n == 262144 {
		return ":T4", nil
	}

	return "", nil
}

//Encrypt tryte string using AES
// the passphrase comes from scrypt, based on the SHA256 hash of the passphrase.
func Encrypt(seed trinary.Trytes, passphrase string, options ScryptOptions) (string, error) {

	if seed == "" {
		return "", errors.New("seed is required")
	}

	if passphrase == "" {
		return "", errors.New("passphrase is required")
	}

	seedBytes, err := trinary.TrytesToBytes(seed)
	if err != nil {
		return "", err
	}

	aesGCM, err := CreateAESCryptor(passphrase, options)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	encryptedSeedBytes := aesGCM.Seal(nil, nonce, seedBytes, nil)

	encryptedSeedTrytes, err := converter.ASCIIToTrytes(hex.EncodeToString(encryptedSeedBytes))
	if err != nil {
		return "", err
	}

	err = trinary.ValidTrytes(encryptedSeedTrytes)
	if err != nil {
		return "", err
	}

	toughness, err := toughnessSetting(options.N)
	if err != nil {
		return "", err
	}

	return encryptedSeedTrytes + toughness, nil
}

func CreateAESCryptor(passphrase string, option ScryptOptions) (cipher.AEAD, error) {

	passphraseBytes := []byte(passphrase)
	hashedPassphrase := sha256.New().Sum(passphraseBytes)

	encryptionKey, err := scrypt.Key(passphraseBytes, hashedPassphrase, option.N, option.R, option.P, option.KeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesGCM, nil
}
