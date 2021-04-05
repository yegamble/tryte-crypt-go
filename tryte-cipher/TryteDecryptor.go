package tryte_cipher

import (
	"encoding/hex"
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
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

	if strings.Contains(*encryptedSeed, ":T1") {
		*encryptedSeed = strings.ReplaceAll(*encryptedSeed, ":T1", "")
		return 32768
	} else if strings.Contains(*encryptedSeed, ":T2") {
		*encryptedSeed = strings.ReplaceAll(*encryptedSeed, ":T2", "")
		return 65536
	} else if strings.Contains(*encryptedSeed, ":T3") {
		*encryptedSeed = strings.ReplaceAll(*encryptedSeed, ":T3", "")
		return 131072
	} else if strings.Contains(*encryptedSeed, ":T4") {
		*encryptedSeed = strings.ReplaceAll(*encryptedSeed, ":T4", "")
		return 262144
	}

	return 16384
}
