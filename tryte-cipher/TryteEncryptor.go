package tryte_cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
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
		options.KeyLen = 32
	}

	if toughnessInput > 9 {
		return "", errors.New("encryption difficulty cannot exceed 9")
	}

	if toughnessInput < 0 {
		return "", errors.New("encryption difficulty cannot be negative")
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

	nonce := make([]byte, aesGCM.NonceSize())
	encryptedSeedBytes := aesGCM.Seal(seedBytes[:0], nonce, seedBytes, nil)
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

//PGP Encrypt, in case the need for local storage of private key
func RSAEncrypt(plaintext []byte, password []byte, packetConfig *packet.Config) (ciphertext []byte, err error) {

	encbuf := bytes.NewBuffer(nil)

	w, err := armor.Encode(encbuf, "PGP MESSAGE", nil)
	if err != nil {
		return
	}
	defer w.Close()

	pt, err := openpgp.SymmetricallyEncrypt(w, password, nil, packetConfig)
	if err != nil {
		return
	}
	defer pt.Close()

	_, err = pt.Write(plaintext)
	if err != nil {
		return
	}

	// Close writers to force-flush their buffer
	pt.Close()
	w.Close()
	ciphertext = encbuf.Bytes()

	return
}

func RSADecrypt(ciphertext []byte, password []byte, packetConfig *packet.Config) (plaintext []byte, err error) {
	decbuf := bytes.NewBuffer(ciphertext)

	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		return
	}

	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		// If the given passphrase isn't correct, the function will be called again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}

	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, packetConfig)
	if err != nil {
		return
	}

	plaintext, err = ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}

	return
}
