package tryte_cipher

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
)

const letters = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ" //pool of letters to generate IOTA seed

func RandomPassphraseGenerator(n int) (string, error) {

	if n < 8 {
		//longer passphrase is more secure enforce this
		return "", errors.New("number of bytes cannot be less than 8")
	}

	b, err := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomSeed returns a securely generated string.
// It will return an error if a secure random int generator
// fails to function correctly
func GenerateRandomSeed() (string, error) {
	ints, err := generateRandomInts(81)

	if err != nil {
		return "", err
	}

	token := make([]byte, 81)

	for i, x := range ints {
		token[i] = intToCharByte(x)
	}

	return string(token), nil
}

func generateRandomInts(n int) ([]int64, error) {
	ints := make([]int64, n)

	for i := range ints {
		randomInt, err := rand.Int(rand.Reader, big.NewInt(27))

		if err != nil {
			return nil, err
		}

		ints[i] = randomInt.Int64()
	}

	return ints, nil
}

func intToCharByte(i int64) byte {
	return letters[i]
}
