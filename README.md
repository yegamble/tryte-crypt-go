# tryte-crypt-go
GoLang package that encrypts tryte strings, including for IOTA private seeds. This is based on [vbakke's tryte-ecrypt library](https://github.com/vbakke/tryte-encrypt) that was written in node.js.

##Installation
`go build main.go`\
`go run main.go`

##Endpoints
After running main.go, the server should start up at port 3000,
allowing navigation to the server using http://127.0.0.1:3000 or localhost:3000.
    
There are two enpoints for this application, /encrypt and /decrypt

Each expects form-data.

### /Encrypt
seed string \
passphrase  string \
difficulty integer 

### /Decrypt
seed string \
passphrase  string 

##Usage

In progress