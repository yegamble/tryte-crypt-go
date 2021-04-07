package tests

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"strconv"
	"strings"
	"testing"
	"time"
)

var seed trinary.Trytes
var defaultOptions tryteCipher.ScryptOptions

func TestMissingPassphraseEncryption(t *testing.T) {

	tryteString, err := tryteCipher.GenerateRandomSeed()
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

	tryteString, err := tryteCipher.GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	passphrase, err := tryteCipher.RandomPassphraseGenerator(64)
	if err != nil || passphrase == "" {
		// Serve an appropriately vague error to the
		// user, but log the details internally.
		log.Println("Test Failed")
		t.Fail()
	}

	testSeed, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(testSeed, passphrase, defaultOptions, 0)
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
	tryteString, err := tryteCipher.GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	passphrase, err := tryteCipher.RandomPassphraseGenerator(64)
	if err != nil || passphrase == "" {
		// Serve an appropriately vague error to the
		// user, but log the details internally.
		log.Println("Test Failed")
		t.Fail()
	}

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	_, err = tryteCipher.Encrypt(test, passphrase, defaultOptions, -1)
	if err != nil {
		log.Println("Test Passed")
	} else {
		t.Error("Negative Numbers Test Failed")
		t.Fail()
	}
}

func TestNegativeNumbersEncrypting(t *testing.T) {
	tryteString, err := tryteCipher.GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	passphrase, err := tryteCipher.RandomPassphraseGenerator(64)
	if err != nil || passphrase == "" {
		// Serve an appropriately vague error to the
		// user, but log the details internally.
		log.Println("Test Failed")
		t.Fail()
	}

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	_, err = tryteCipher.Encrypt(test, passphrase, defaultOptions, -1)
	if err != nil {
		log.Println("Test Passed")
	} else {
		t.Error("Negative Numbers Test Failed")
		t.Fail()
	}

}

func TestWrongSeed(t *testing.T) {

	for i := 0; i < 5; i++ {
		tryteString, err := tryteCipher.GenerateRandomSeed()
		if err != nil {
			log.Println(err)
			t.Fail()
		}

		passphrase, err := tryteCipher.RandomPassphraseGenerator(64)
		if err != nil || passphrase == "" {
			// Serve an appropriately vague error to the
			// user, but log the details internally.
			log.Println("Test Failed")
			t.Fail()
		}

		log.Println("Passphrase: " + passphrase)

		test, err := trinary.NewTrytes(tryteString)

		//var options scryptOptions
		run, err := tryteCipher.Encrypt(test, passphrase, defaultOptions, i)
		if err != nil {
			log.Fatal(err)
			t.Fail()
		}
		log.Println("Encrypted: " + run)

		start := time.Now()

		//var options scryptOptions
		wrongSeed, err := tryteCipher.Encrypt(test, passphrase+"l", defaultOptions, i)
		if err != nil {
			log.Fatal(err)
			t.Fail()
		}
		log.Println("Encrypted: " + wrongSeed)

		run3, err := tryteCipher.Decrypt(wrongSeed, passphrase, defaultOptions)
		if err != nil {
			log.Println(err)
		} else {
			t.Fail()
		}

		if strings.Compare(tryteString, run3) != 0 {
			log.Println("Test Pass")
		} else if strings.Compare(tryteString, run3) == 0 {
			log.Println("Decrypted: " + run3)
			log.Println(time.Since(start))
			log.Println("Test Failed")
			t.Fail()
		}
	}

}

func TestRandomPassphraseGenerator(t *testing.T) {

	for i := 1; i < 64; i++ {
		passphrase, err := tryteCipher.RandomPassphraseGenerator(i)
		if err != nil || passphrase == "" {

			if i < 8 {
				log.Println(err)
				log.Println("Test Passed")
			} else {
				// Serve an appropriately vague error to the
				// user, but log the details internally.
				log.Println("Passphrase generator failed at iteration " + strconv.Itoa(i))
				t.Fail()
			}
		}
		log.Println(passphrase)
	}

	log.Println("Test Passed")
}

func TestIfSeedIsCorrect(t *testing.T) {

	for i := 0; i < 5; i++ {

		passphrase, err := tryteCipher.RandomPassphraseGenerator(64)
		if err != nil || passphrase == "" {
			// Serve an appropriately vague error to the
			// user, but log the details internally.
			log.Println("Test Failed")
			t.Fail()
		}

		log.Println("Passphrase: " + passphrase)

		tryteString, err := tryteCipher.GenerateRandomSeed()
		if err != nil {
			log.Println(err)
			t.Fail()
		}

		test, err := trinary.NewTrytes(tryteString)

		//var options scryptOptions
		run, err := tryteCipher.Encrypt(test, passphrase, defaultOptions, i)
		if err != nil {
			log.Println(err)
			t.Fail()
		}
		log.Println("Encrypted: " + run)

		start := time.Now()

		run2, err := tryteCipher.Decrypt(run, passphrase, defaultOptions)
		if err != nil {
			log.Println(err)
			t.Fail()
		}

		log.Println("Decrypted: " + run2)
		log.Println(time.Since(start))

		if strings.Compare(tryteString, run2) != 0 {
			log.Println("Test Failed")
			t.Fail()
		} else if strings.Compare(tryteString, run2) == 0 {
			log.Println("Test Passed")
		}
	}

}
