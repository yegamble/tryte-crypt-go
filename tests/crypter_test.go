package tests

import (
	"github.com/iotaledger/iota.go/trinary"
	tryteCipher "github.com/yegamble/tryte-crypt-go/tryte-cipher"
	"log"
	"strings"
	"testing"
)

var seed trinary.Trytes
var defaultOptions tryteCipher.ScryptOptions

type tests struct {
	seed       string
	passphrase string
	options    tryteCipher.ScryptOptions
}

func init() {
	defaultOptions.N = 16384
	defaultOptions.R = 8
	defaultOptions.P = 8
	defaultOptions.KeyLen = 16
}

func TestMissingPassphrase(t *testing.T) {
	tryteString := "A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z"
	test, err := trinary.NewTrytes(tryteString)

	//var options scryptOptions
	run, err := tryteCipher.Encrypt(test, "test", defaultOptions)
	if err != nil {
		log.Println(err)
		t.Fail()
		return
	}

	run2, err := tryteCipher.Decrypt(run, "test", defaultOptions)
	if err != nil {
		log.Println(err)
		t.Fail()
		return
	}

	if strings.Compare(tryteString, run2) != 0 {
		log.Println("Test Failed")
	} else if strings.Compare(tryteString, run2) == 0 {
		log.Println("Test Passed")
	}

}
