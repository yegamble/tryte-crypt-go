package main

import (
	"crypto/rand"
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"math/big"
	"strings"
	"time"
)

var defaultOptions tryteCipher.ScryptOptions

func init() {

}

const letters = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ" //pool of letters to generate IOTA seed

func main() {
	start := time.Now()

	tryteString, err := GenerateRandomSeed()
	if err != nil {
		log.Println(err)
	}

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "test", defaultOptions, 2)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Encrypted: " + run)

	start = time.Now()
	run2, err := tryteCipher.Decrypt(run, "test", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Decrypted: " + run2)
	log.Println(time.Since(start))

	if strings.Compare(tryteString, run2) != 0 {
		log.Println("Test Failed")
	} else if strings.Compare(tryteString, run2) == 0 {
		log.Println("Test Passed")
	}
}
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
	return byte(letters[i])
}
