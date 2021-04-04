package main

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
)

func main() {

	test, err := trinary.NewTrytes("JNMNJIEHRQ9PIQWNTTSG9HRDFNOZ9KAKYSIJFOOGGCRKNHXFHGQGOKORP9CUVYNUWDVXLFRUZPXWUMOJ9")
	var defaultOptions tryteCipher.ScryptOptions
	defaultOptions.N = 16384
	defaultOptions.R = 8
	defaultOptions.P = 8
	defaultOptions.KeyLen = 32

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "Spider13424324234321", defaultOptions)
	if err != nil {
		log.Fatal(err)
	}

	//run2, err := decrypt(test, "Spider13424324234321",testOptions)
	//if err != nil {
	//	log.Fatal(err)
	//}

	log.Println(run)

}
