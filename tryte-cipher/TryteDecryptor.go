package tryte_cipher

import (
	"encoding/hex"
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
)

func Decrypt(encryptedSeed trinary.Trytes, passphrase string, options ScryptOptions) (trinary.Trytes, error) {

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

	plaintext := hex.EncodeToString(openSeed)

	tryteDecryptedSeed, err := converter.ASCIIToTrytes(plaintext)
	if err != nil {
		return "", err
	}

	return tryteDecryptedSeed, nil
}
