package tests

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"strings"
	"testing"
	"time"
)

var seed trinary.Trytes
var defaultOptions tryteCipher.ScryptOptions

type tests struct {
	seed       string
	passphrase string
	options    tryteCipher.ScryptOptions
}

func init() {

}

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
	tryteString, err := tryteCipher.GenerateRandomSeed()
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	_, err = tryteCipher.Encrypt(test, "qwerty123456", defaultOptions, -1)
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

	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	_, err = tryteCipher.Encrypt(test, "qwerty123456", defaultOptions, -1)
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

		test, err := trinary.NewTrytes(tryteString)

		//var options scryptOptions
		run, err := tryteCipher.Encrypt(test, "qwerty123456", defaultOptions, i)
		if err != nil {
			log.Fatal(err)
			t.Fail()
		}
		log.Println("Encrypted: " + run)

		start := time.Now()

		wrongSeed := "PCCBXAZAUCQCABBBAB9BRCUCRCABQCXAZASCUCUATCUCRCABRCUAXAYAQCSCUAPCRCBBYAVAQCTCPCABXAPCVABBVAQCZASCUAYAZATCYA9B9BUAPCWAABBBRCYAUCCBUCTCZAYAPCTCABBBTCZAWA9BYA9BTCCBYAUCXAQCVAVACBYAXAVAYAPCUCWABBBBVAWACBABQCCBYAUCZABBPCWAXA9BBBUCYAVAWAABUASCXAYAQCUCCBZAUABBQCYATCYA:T2"
		run2, err := tryteCipher.Decrypt(wrongSeed, "qwerty123456", defaultOptions)
		if err != nil {
			log.Println(err)
		} else {
			t.Fail()
		}

		if strings.Compare(tryteString, run2) != 0 {
			log.Println("Test Pass")
		} else if strings.Compare(tryteString, run2) == 0 {
			log.Println("Decrypted: " + run2)
			log.Println(time.Since(start))
			log.Println("Test Failed")
			t.Fail()
		}
	}

}

func TestIfSeedIsCorrect(t *testing.T) {

	for i := 0; i < 5; i++ {
		tryteString, err := tryteCipher.GenerateRandomSeed()
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
