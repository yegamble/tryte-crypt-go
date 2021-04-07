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

var loggingTime time.Time

//Determine if the toughness level should be printed in the encrypted seed
func ToughnessSetting(n int) (toughness string, err error) {

	toughnessInt, err := FindPowerOfNToughness(n)
	if err != nil {
		return
	}

	if toughnessInt > 0 {
		toughness = ":T" + strconv.Itoa(toughnessInt)
	}

	return
}

//Calculate the number of bits based on user input that is greater than 0
func FindPowerOfNToughness(n int) (bits int, err error) {

	if n%2 != 0 {
		err = errors.New("number is not a power of 2")
		return
	}

	for i := 0; i < n; i++ {

		if int(math.Pow(2, float64(i))) == n {
			bits = i - 14
			return
		}

	}
	return
}

//Encrypt tryte string using AES
// the passphrase comes from scrypt, based on the SHA256 hash of the passphrase.
// takes seed Tryte, passphrase of any string, optional ScryptOptions struct
//Alternatively toughnessInput will calculate the required settings for AES
func Encrypt(seed trinary.Trytes, passphrase string, options ScryptOptions, toughnessInput int) (result string, err error) {
	loggingTime = time.Now()

	//Default Options for AES
	if options.N == 0 {
		options.N = int(math.Pow(2, float64(toughnessInput+14)))
		options.R = 8 + toughnessInput
		options.P = 8 + toughnessInput
		options.KeyLen = 32
	}

	if toughnessInput > 9 {
		err = errors.New("encryption difficulty cannot exceed 9")
		return
	}

	if toughnessInput < 0 || options.N < 0 {
		err = errors.New("encryption difficulty cannot be negative")
		return
	}

	if seed == "" {
		err = errors.New("seed is required")
		return
	}

	if passphrase == "" {
		err = errors.New("passphrase is required")
		return
	}

	seedBytes, err := trinary.TrytesToBytes(seed)
	if err != nil {
		return
	}

	log.Println("seed converted to bytes")

	aesGCM, err := CreateAESCryptor(passphrase, options)
	if err != nil {
		return
	}

	nonce := make([]byte, aesGCM.NonceSize())
	encryptedSeedBytes := aesGCM.Seal(seedBytes[:0], nonce, seedBytes, nil)
	log.Println("seed encrypted, now converting to ASCII")

	encryptedSeedTrytes, err := converter.ASCIIToTrytes(hex.EncodeToString(encryptedSeedBytes))
	if err != nil {
		return
	}
	log.Println(time.Since(loggingTime))

	err = trinary.ValidTrytes(encryptedSeedTrytes)
	if err != nil {
		return
	}

	toughness, err := ToughnessSetting(options.N)
	if err != nil {
		return
	}

	result = encryptedSeedTrytes + toughness

	return
}

//initialise Cipher with passphrase and options set in ScryptOptions struct
func CreateAESCryptor(passphrase string, option ScryptOptions) (aesGCM cipher.AEAD, err error) {

	passphraseBytes := []byte(passphrase)
	hashedPassphrase := sha256.New().Sum(sha256.New().Sum(passphraseBytes))

	encryptionKey, err := scrypt.Key(passphraseBytes, hashedPassphrase, option.N, option.R, option.P, option.KeyLen)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return
	}

	aesGCM, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	return
}
