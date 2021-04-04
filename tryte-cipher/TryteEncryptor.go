package tryte_cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"github.com/iotaledger/iota.go/trinary"
	"golang.org/x/crypto/scrypt"
)

type ScryptOptions struct {
	N      int
	R      int
	P      int
	KeyLen int
}

//Encrypt tryte string using AES
// the passphrase comes from scrypt, based on the SHA256 hash of the passphrase.
func Encrypt(seed trinary.Trytes, passphrase string, options ScryptOptions) ([]byte, error) {

	seedBytes, err := trinary.TrytesToBytes(seed)
	if err != nil {
		return nil, err
	}

	ciphertext, err := CreateAESCryptor(seedBytes, passphrase, options)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func CreateAESCryptor(seedBytes []byte, passphrase string, option ScryptOptions) ([]byte, error) {

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

	nonce := make([]byte, 12)

	ciphertext := aesGCM.Seal(nil, nonce, seedBytes, nil)

	return ciphertext, nil
}
