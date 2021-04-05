# tryte-crypt-go
GoLang package that encrypts tryte strings, including for IOTA private seeds. This is based on [vbakke's tryte-ecrypt library](https://github.com/vbakke/tryte-encrypt) that was written in JavaScript.

## CMD Line
`go build cmd.go`\
`go run cmd.go`

Follow the instructions in command line to encrypt and existing seed or generate a new seed. Recommended use is offline.

## Server Installation
`go build main.go`\
`go run main.go`

## Endpoints (Recommended Offline Use Only)
To make this simple to use, I made 3 endpoints. I do not recommend using this on a website to generate seeds, only if you build offline and generate yourself.

After running main.go, the server should start up at port 3000,
allowing navigation to the server using http://127.0.0.1:3000 or localhost:3000.
    
The following enpdoints for this application, /encrypt and /decrypt each expect form-data.

### /encrypt
seed string \
passphrase  string \
difficulty integer 

### /decrypt
seed string \
passphrase  string 

### /generate
passphrase string \
difficulty int 

## Usage

Raw IOTA Seed 
`A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z`

Encrypted Seed
`ABABZASCVAPCBBWAZAWATCTCVAZAUASCYASCYAYARCYACBRCUCSCQCXAQCSCQCWAVAABPCYAYACBRCTCTCUCTCBBTCUCABCBVAZAUCZARCZA9BYAZATCXACBABZAUAUCTCBBVARCABBBYA9BSCABVARCXAWAWAWAYA9BUCCB9B9BRCXAZAZACBUCSCYAABWAXAXARCCB9BUATCYASCUAABZARCWAABSCCBPCSC9BVAXAUCWAWACBZAYAABPCZARCVAWA:T4`


