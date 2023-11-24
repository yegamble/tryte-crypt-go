[![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/yegamble/tryte-crypt-go/Go/master)](https://github.com/yegamble/tryte-crypt-go/actions/workflows/go.yml)   [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fyegamble%2Ftryte-crypt-go.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fyegamble%2Ftryte-crypt-go?ref=badge_shield)


# tryte-crypt-go
Disclaimer: DO NOT Send Your Crypto to seeds generated with this program. Only use IOTA Foundation apps or generate your seed offline.

This GoLang package encrypts tryte strings, including for IOTA private seeds. This is based on [vbakke's tryte-encrypt library](https://github.com/vbakke/tryte-encrypt) that was written in JavaScript.

This package is not fully standardised to vbakke's library, notably CTR mode is not used due to some issues decoding keys, xChaCha20-Poly1305 is used.

## CMD Line Usage

`go build cmd.go`\
`go run cmd.go`

Follow the instructions in command line to encrypt and existing seed or generate a new seed. Recommended use is offline on an air gapped machine.

Raw IOTA Seed (using the passphrase "test" at 4 difficulty)
`A999TEST999SEED99999999999999999999999999999999999999999999999999999999999999999Z`

Encrypted Seed
`TCYABB9BQCABWACBVAVAWARCBBVAXAVAYAABZAWAXA9BUACBRCYAUACBZAWAPCSCTCPCUCVAWAABABVASCSCYAUAUC9BWAUASC9BCBSC9BUAYAVACBPC9BXA9BBBQCXAYAZAYABBABYACB9B9BZAUABBVAABUAPCYAZAZARCUCQCWARCUAUCABZATCRCPCSCYAABWAABXAWAYAQCPCRCYAUC9BUA9BAB9BZAPCWACBRCXAVAXAWAVAAB9BPCRCTCRCABSCQCYAWATCWAUCSCVAVAUCZATCSCQCABZAYATCBBUAPCBB9BWAZA9BCBRCRCPCPCRCSCUASCWAYAABRCXAWACBXAZAZAQCVA:T4`


## Server Installation
`go build main.go`\
`go run main.go`

## Endpoints (Recommended Offline Use Only)
To make this simple to use, 3 endpoints were created. I do not recommend using this on a website to generate seeds, only if you build offline and generate yourself.

| Endpoint  | Form Data                                                           |                                                                                                          
| :---------| :-------------------------------------------------------------------|
| /encrypt  | **seed:** string, **passphrase:** string, **difficulty:** integer   | 
| /decrypt  | **seed:** string, **passphrease:** string                           |                                                                                                          
| /generate | **passphrease:** string, **difficulty:** string                     |  

After running main.go, the server should start up at port 3000,
allowing navigation to the server using http://127.0.0.1:3000 or localhost:3000.
    
The following enpdoints for this application, /encrypt and /decrypt each expect form-data.

<img width="1395" alt="image" src="https://user-images.githubusercontent.com/9465387/113575799-8c58cc80-9672-11eb-98ae-4a71b478d848.png">                                                                                                           

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fyegamble%2Ftryte-crypt-go.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fyegamble%2Ftryte-crypt-go?ref=badge_large)
