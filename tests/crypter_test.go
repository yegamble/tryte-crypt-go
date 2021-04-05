package tests

import (
	"crypto/rand"
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"math/big"
	"strings"
	"testing"
	"time"
)

var seed trinary.Trytes
var defaultOptions tryteCipher.ScryptOptions

const letters = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ" //pool of letters to generate IOTA seed

type tests struct {
	seed       string
	passphrase string
	options    tryteCipher.ScryptOptions
}

func init() {

}

func TestMissingPassphraseEncryption(t *testing.T) {

	tryteString, err := GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	testSeed, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(testSeed, "", defaultOptions, 0)
	if err != nil {
		log.Println("Test Passed")
	} else if run != "" {
		t.Fail()
	}

}

func TestMissingPassphraseDecryption(t *testing.T) {

	tryteString, err := GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	testSeed, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(testSeed, "qwerty123456", defaultOptions, 0)
	if err != nil {
		log.Println("Test Passed")
	}

	log.Println("Encrypted: " + run)

	start := time.Now()

	run2, err := tryteCipher.Decrypt(run, "", defaultOptions)
	if err != nil {
		log.Println(err)

	} else if run2 != "" {
		t.Fail()
	}

	log.Println("Decrypted: " + run2)
	log.Println(time.Since(start))

	if strings.Compare(tryteString, run2) != 0 {
		log.Println("Test Failed")
	} else if strings.Compare(tryteString, run2) == 0 {
		log.Println("Test Passed")
	}

}

func TestNegativeNumbersDecrypting(t *testing.T) {
	tryteString, err := GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	_, err = tryteCipher.Encrypt(test, "qwerty123456", defaultOptions, -1)
	if err != nil {
		log.Println("Test Passed")
	}
}

func TestNegativeNumbersEncrypting(t *testing.T) {
	tryteString, err := GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	_, err = tryteCipher.Encrypt(test, "qwerty123456", defaultOptions, -1)
	if err != nil {
		log.Println("Test Passed")
	}

}

func TestIfSeedIsCorrect(t *testing.T) {

	for i := 0; i < 4; i++ {
		tryteString, err := GenerateRandomSeed()
		if err != nil {
			log.Println(err)
			t.Fail()
		}

		test, err := trinary.NewTrytes(tryteString)

		//var options scryptOptions
		run, err := tryteCipher.Encrypt(test, "qwerty123456", defaultOptions, i)
		if err != nil {
			log.Fatal(err)
			t.Fail()
		}
		log.Println("Encrypted: " + run)

		start := time.Now()

		run2, err := tryteCipher.Decrypt(run, "qwerty123456", defaultOptions)
		if err != nil {
			log.Fatal(err)
			t.Fail()
		}

		log.Println("Decrypted: " + run2)
		log.Println(time.Since(start))

		if strings.Compare(tryteString, run2) != 0 {
			log.Println("Test Failed")
		} else if strings.Compare(tryteString, run2) == 0 {
			log.Println("Test Passed")
		}
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
