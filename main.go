package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"github.com/iotaledger/iota.go/trinary"
	"golang.org/x/crypto/scrypt"
	"log"
)

type  scryptOptions struct{
	N    int
	r 	 int
	p    int
	keyLen int
}

func main(){

	test, err := trinary.NewTrytes("JNMNJIEHRQ9PIQWNTTSG9HRDFNOZ9KAKYSIJFOOGGCRKNHXFHGQGOKORP9CUVYNUWDVXLFRUZPXWUMOJ9")
	var testOptions scryptOptions
	testOptions.N = 32768
	testOptions.r = 8
	testOptions.p = 8
	testOptions.keyLen = 32

	//var options scryptOptions
	run, err := encrypt(test, "Spider13424324234321",testOptions)
	if err != nil {
		log.Fatal(err)
	}

	//run2, err := decrypt(test, "Spider13424324234321",testOptions)
	//if err != nil {
	//	log.Fatal(err)
	//}

	log.Println(run)

}


func decrypt(encryptedSeed string, passphrase string, options scryptOptions){

}

//Encrypt tryte string using AES
// the passphrase comes from scrypt, based on the SHA256 hash of the passphrase.
func encrypt(seed trinary.Trytes, passphrase string, options scryptOptions) ([]byte, error){

	seedBytes, err := trinary.TrytesToBytes(seed)
	if err != nil {
		return nil, err
	}

	_,aead , nonce, err := createAESCryptor(passphrase, options)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, seedBytes, nil)
	fmt.Printf("%x\n", ciphertext)
	//
	//var encryptedSeedBytes []byte
	//cryptor.Encrypt(nil, seedBytes)

	return ciphertext, nil
}

func createAESCryptor(passphrase string, option scryptOptions) (cipher.Block, cipher.AEAD, []byte, error){

	passphraseBytes := []byte(passphrase)
	hashedPassphrase := sha256.New().Sum(passphraseBytes)

	encryptionKey, err := scrypt.Key(passphraseBytes, hashedPassphrase, option.N, option.r, option.p,option.keyLen)
	if err != nil {
		return nil, nil, nil, err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce := make([]byte, 12)

	return block,aesGCM, nonce, nil
}

