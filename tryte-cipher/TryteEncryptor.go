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
	"log"
	"math"
	"strconv"
	"time"
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

var loggingTime time.Time

//Calculate the number of bits based on user input that is greater than 0
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
// takes seed Tryte, passphrase of any string, optional ScryptOptions struct
//Alternatively toughnessInput will calculate the required settings for AES
func Encrypt(seed trinary.Trytes, passphrase string, options ScryptOptions, toughnessInput int) (string, error) {
	loggingTime = time.Now()

	//Default Options for AES
	if options.N == 0 {
		options.N = int(math.Pow(2, float64(toughnessInput+14)))
		options.R = 8 + toughnessInput
		options.P = 8 + toughnessInput
		options.KeyLen = 16
	}

	if toughnessInput > 9 {
		return "", errors.New("encryption difficulty cannot exceed 9")
	}

	if options.N < 0 {
		return "", errors.New("encryption difficulty cannot be negative")
	}

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

	log.Println("seed converted to bytes")

	aesGCM, err := CreateAESCryptor(passphrase, options)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	encryptedSeedBytes := aesGCM.Seal(nil, nonce, seedBytes, nil)
	log.Println("seed encrypted, now converting to ASCII")

	encryptedSeedTrytes, err := converter.ASCIIToTrytes(hex.EncodeToString(encryptedSeedBytes))
	if err != nil {
		return "", err
	}
	log.Println(time.Since(loggingTime))

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

//initialise Cipher with passphrase and options set in ScryptOptions struct
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
