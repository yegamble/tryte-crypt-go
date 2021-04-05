package main

import (
	"github.com/iotaledger/iota.go/converter"
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"strings"
)

func main() {

	tryteString := "A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z"
	test, err := trinary.NewTrytes(tryteString)

	var defaultOptions tryteCipher.ScryptOptions
	defaultOptions.N = 8192
	defaultOptions.R = 8
	defaultOptions.P = 8
	defaultOptions.KeyLen = 16

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "test", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	run2, err := tryteCipher.Decrypt(run, "test", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Encrypted: " + run)
	log.Println("Decrypted: " + run2)

	test2, _ := converter.TrytesToASCII(run2)

	if strings.Compare(run2, test2) != 0 {
		log.Println("Test Failed")
	}
}
