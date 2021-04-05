package main

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"strings"
)

func main() {

	tryteString := "A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z"
	test, err := trinary.NewTrytes(tryteString)

	var defaultOptions tryteCipher.ScryptOptions
	defaultOptions.N = 16384
	defaultOptions.R = 8
	defaultOptions.P = 8
	defaultOptions.KeyLen = 32

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "Ƥāssφräsę", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	run2, err := tryteCipher.Decrypt(run, "Ƥāssφräsę", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(run)
	log.Println(run2)

	if strings.Compare(tryteString, run2) != 0 {
		log.Println("Test Failed")
	}
}
