package tryte_cipher

import (
	"encoding/hex"
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
	"math"
	"strconv"
	"strings"
)

//Decrypt an Encrypted Tryte Seed
func Decrypt(encryptedSeed trinary.Trytes, passphrase string, options ScryptOptions) (tryteDecryptedSeed trinary.Trytes, err error) {

	options.N, options = getToughnessFromSeed(&encryptedSeed, options)

	asciiEncryptedSeed, err := converter.TrytesToASCII(encryptedSeed)
	if err != nil {
		return
	}

	encryptedSeedBytes, err := hex.DecodeString(asciiEncryptedSeed)
	if err != nil {
		return
	}

	aead, err := CreateAESCryptor(passphrase, options)
	if err != nil {
		return
	}

	nonce, ciphertext := encryptedSeedBytes[:aead.NonceSize()], encryptedSeedBytes[aead.NonceSize():]

	//nonce := make([]byte, aead.NonceSize())
	openSeed, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	tryteDecryptedSeed, err = trinary.BytesToTrytes(openSeed, 81)
	if err != nil {
		return
	}

	return
}

//find the difficulty within the string seed
func getToughnessFromSeed(encryptedSeed *string, options ScryptOptions) (int, ScryptOptions) {

	if strings.Contains(*encryptedSeed, ":T") {
		lastChar := (*encryptedSeed)[len(*encryptedSeed)-1:]
		*encryptedSeed = strings.ReplaceAll(*encryptedSeed, ":T"+lastChar, "")

		power, err := strconv.Atoi(lastChar)
		if err != nil {
			return 0, options
		}

		options.N = int(math.Pow(2, float64(power+14)))
		options.R = 8 + power
		options.P = 8 + power
		options.KeyLen = 32

		toughness := int(math.Pow(2, float64(power+14)))

		return toughness, options
	}

	options.N = int(math.Pow(2, float64(14)))
	options.R = 8
	options.P = 8
	options.KeyLen = 32

	return 16384, options
}
