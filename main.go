package main

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"strings"
	"time"
)

var defaultOptions tryteCipher.ScryptOptions

func init() {
	defaultOptions.N = 1048576
	defaultOptions.R = 12
	defaultOptions.P = 12
	defaultOptions.KeyLen = 16
}

func main() {
	start := time.Now()

	tryteString := "A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z"
	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "test", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Encrypted: " + run)
	log.Println(time.Since(start))

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
