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

	options.N = getToughnessFromSeed(&encryptedSeed)

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

func getToughnessFromSeed(encryptedSeed *string) int {

	if strings.Contains(*encryptedSeed, ":T") {
		lastChar := (*encryptedSeed)[len(*encryptedSeed)-1:]
		*encryptedSeed = strings.ReplaceAll(*encryptedSeed, ":T"+lastChar, "")

		power, err := strconv.Atoi(lastChar)
		if err != nil {
			return 0
		}

		toughness := int(math.Pow(2, float64(power+14)))

		return toughness
	}

	return 16384
}
