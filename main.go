package main

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
)

var defaultOptions tryteCipher.ScryptOptions

func init() {
	defaultOptions.N = 262144
	defaultOptions.R = 8
	defaultOptions.P = 8
	defaultOptions.KeyLen = 16
}

func main() {

	tryteString := "A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z"
	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "test", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	//run2, err := tryteCipher.Decrypt(run, "test", defaultOptions)
	//if err != nil {
	//	log.Fatal(err)
	//}

	log.Println("Encrypted: " + run)
	//log.Println("Decrypted: " + run2)
	//
	//if strings.Compare(tryteString, run2) != 0 {
	//	log.Println("Test Failed")
	//} else if strings.Compare(tryteString, run2) == 0 {
	//	log.Println("Test Passed")
	//}
}
