package tryte_cipher

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
)

const letters = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ" //pool of letters to generate IOTA seed

func RandomPassphraseGenerator(n int) (stringBytes string, err error) {

	if n < 8 {
		//longer passphrase is more secure enforce this
		err = errors.New("number of bytes cannot be less than 8")
		return
	}

	randomPassphraseBytes, err := GenerateRandomBytes(n)
	stringBytes = base64.URLEncoding.EncodeToString(randomPassphraseBytes)

	return
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
func GenerateRandomSeed() (seed string, err error) {
	ints, err := generateRandomInts(81)

	if err != nil {
		return
	}

	token := make([]byte, 81)

	for i, x := range ints {
		token[i] = intToCharByte(x)
	}

	seed = string(token)

	return
}

func generateRandomInts(n int) (ints []int64, err error) {
	ints = make([]int64, n)

	for i := range ints {
		randomInt, err := rand.Int(rand.Reader, big.NewInt(27))

		if err != nil {
			return nil, err
		}

		ints[i] = randomInt.Int64()
	}

	return
}

func intToCharByte(i int64) byte {
	return letters[i]
}
