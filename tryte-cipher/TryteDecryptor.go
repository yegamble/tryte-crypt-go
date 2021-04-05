package tryte_cipher

import (
	"encoding/hex"
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
	"math"
	"strconv"
	"strings"
)

func Decrypt(encryptedSeed trinary.Trytes, passphrase string, options ScryptOptions) (trinary.Trytes, error) {

	options.N, options = getToughnessFromSeed(&encryptedSeed, options)

	asciiEncryptedSeed, err := converter.TrytesToASCII(encryptedSeed)
	if err != nil {
		return "", err
	}

	encryptedSeedBytes, err := hex.DecodeString(asciiEncryptedSeed)
	if err != nil {
		return "", err
	}

	aesGCM, err := CreateAESCryptor(passphrase, options)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	openSeed, err := aesGCM.Open(nil, nonce, encryptedSeedBytes, nil)
	if err != nil {
		return "", err
	}

	tryteDecryptedSeed, err := trinary.BytesToTrytes(openSeed, 81)
	if err != nil {
		return "", err
	}

	return tryteDecryptedSeed, nil
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
