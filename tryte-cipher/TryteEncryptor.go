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
	"math"
	"strconv"
)

type TryteEncryptor interface{}

type ScryptOptions struct {
	N      int
	R      int
	P      int
	KeyLen int
}

func ToughnessSetting(n int) (string, error) {

	toughness, err := FindPowerOfNToughness(n)
	if err != nil {
		return "", err
	}

	if toughness > 0 {
		return ":T" + strconv.Itoa(toughness), nil
	}
	return "", nil
}

func FindPowerOfNToughness(n int) (int, error) {

	if n%2 != 0 {
		return 0, errors.New("number is not a power of 2")
	}

	for i := 0; i < n; i++ {

		if int(math.Pow(2, float64(i))) == n {
			return i - 14, nil
		}

	}

	return -1, nil
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

	toughness, err := ToughnessSetting(options.N)
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
