# golang-jwt for PKCS11

Another extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) that allows creating and verifying JWT tokens where the private key is embedded inside Hardware like HSM, TPM or Yubikeys.   Unlike the following:

* [golang-jwt for Yubikey](https://github.com/salrashid123/golang-jwt-yubikey)
* [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)

This library abstracts the interface away to those devices by using PKCS11.


for reference, see 

* [YubiKeyTokenSource](https://github.com/salrashid123/yubikey)
* [PKCS 11 Samples in Go using SoftHSM](https://github.com/salrashid123/go_pkcs11)
* [mTLS with PKCS11](https://github.com/salrashid123/mtls_pkcs11)

>> NOTE: this is just a proof of concept/alpha quality!  caveat emptor.  I also find PKCS11 support pretty inconsistent.  Its better to use the native integrations


### Supported Algorithms

* `RSA-2048`

(i just didn't'' have the time to account for the additional types)

### Setup (softHSM)

First [install softHSM](https://github.com/opendnssec/SoftHSMv2).

Then make create a key and generate a JWT

```bash
sudo apt-get install libsofthsm2-dev opensc

mkdir -p $HOME/soft_hsm/tokens

$ cat /path/to/softhsm.conf 
log.level = DEBUG
objectstore.backend = file
directories.tokendir = /path/to/soft_hsm/tokens
slots.removable = true

export SOFTHSM2_CONF=/path/to/softhsm.conf

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-mechanisms --slot-index 0

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
      Available slots:
      Slot 0 (0x54349ba6): SoftHSM slot ID 0x54349ba6
        token label        : token1
        token manufacturer : SoftHSM project
        token model        : SoftHSM v2
        token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
        hardware version   : 2.6
        firmware version   : 2.6
        serial num         : bae0cdf454349ba6
        pin min/max        : 4/255
      Slot 1 (0x1): SoftHSM slot ID 0x1
        token state:   uninitialized


$ softhsm2-util --show-slots
      Available slots:
      Slot 859281362
          Slot info:
              Description:      SoftHSM slot ID 0x333797d2                                      
              Manufacturer ID:  SoftHSM project                 
              Hardware version: 2.6
              Firmware version: 2.6
              Token present:    yes
          Token info:
              Manufacturer ID:  SoftHSM project                 
              Model:            SoftHSM v2      
              Hardware version: 2.6
              Firmware version: 2.6
              Serial number:    0c1edf42333797d2
              Initialized:      yes
              User PIN init.:   yes
              Label:            token1                          
      Slot 1
          Slot info:
              Description:      SoftHSM slot ID 0x1                                             
              Manufacturer ID:  SoftHSM project                 
              Hardware version: 2.6
              Firmware version: 2.6
              Token present:    yes
          Token info:
              Manufacturer ID:  SoftHSM project                 
              Model:            SoftHSM v2      
              Hardware version: 2.6
              Firmware version: 2.6
              Serial number:                    
              Initialized:      no
              User PIN init.:   no
              Label:               

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin
      Using slot 0 with a present token (0x1ccdc205)
      Key pair generated:
      Private Key Object; RSA 
        label:      keylabel1
        ID:         4142
        Usage:      decrypt, sign, unwrap
        Access:     sensitive, always sensitive, never extractable, local
      Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, wrap
        Access:     local


      Using slot 0 with a present token (0x1ccdc205)
      Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, wrap
        Access:     local


    $ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects
      Using slot 0 with a present token (0x333797d2)
      Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, wrap
        Access:     local
```


```log
# cd examples/
$ go run main.go 

$ go run main.go 
2022/10/03 06:26:19      PublicKey: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qjbdskV5yP/dOKVPTe4
S9HxnVC9wP1NqS/sqqQ4ZDXu5Ffkv/6hlefHj99W27jEaAA6iEK2U7qQKVsDJqAq
G888ZA+72NnxZ6FKUI7d7o+gZP8p/sTyfLdNmIhlRWclAahS6/845jThUf/OkZi4
54gRT2RECDRSwfU/qOLCKUPc7Adpc14MNrzD52Grozj4MyzNInVJWP3rBSMfyDT9
CULfrhc2FlqdkQsp4F2QY6CLXixQxVXW/ejjTezlFWz9a6tqFQV3jfYY6qBYAdDF
0/U5IlVYTeMAU4Sjfmum7JdAHx6HpAw6mGIQG5w1LzEaTggmavd/dkyywI7yZC7A
iQIDAQAB
-----END PUBLIC KEY-----
2022/10/03 06:26:19 Token: eyJhbGciOiJSUzI1NiIsImtpZCI6InJTcGs2S050TXhvejNuYW9tTFNnWDJGVlBaZ2cxajVnMVJIWVVkamE0U2ciLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2NjQ3OTI4MzksImlzcyI6InRlc3QifQ.H_iag9Cm1O9jWkDnayz0grz4dEpWoIoYaoqptwGGnOn8qNBzNQCspk3jMpKV-rFnxAiRfslqnI8-Y8cObqtZxoJ9f7DfnqUycJGG-4yG7m1-VYdOcJe3LIH0mtqdHOf_XtlXaLxKpiCxnMn0H9WL541SW3JwONvLIKHeZgsn2j03I9bsN5k7-cHzofowIf_iPAF-N9GoTt0ukh0FdIcQYOH4mU5XVE_zObTmF-bfQ_83pLYcOEUDDMm9Tv6Mnw9_GqUtuqLN-4X_17jXaGjQm7pEapaDdvKWiEZkWtcKxu0PA6hXjcsHVN7WH5g4YaRoXlGLKFH6Nmu6hIMYFqewBg
2022/10/03 06:26:19      verified with PublicKey
2022/10/03 06:26:19      verified with exported PubicKey


```

The JWT is formatted as:

```json
{
  "alg": "RS256",
  "kid": "rSpk6KNtMxoz3naomLSgX2FVPZgg1j5g1RHYUdja4Sg",
  "typ": "JWT"
}
{
  "exp": 1664792839,
  "iss": "test"
}
```

Where the `keyID` is the base64 encoded hash of the DER public key as shown below (it can be anything you want)

```bash
$ openssl rsa -pubin -in publickey.pem -outform DER | openssl sha256
writing RSA key
SHA256(stdin)= ad2a64e8a36d331a33de76a898b4a05f61553d9820d63e60d511d851d8dae128

# base64 of hex ad2a64e8a36d331a33de76a898b4a05f61553d9820d63e60d511d851d8dae128 --> rSpk6KNtMxoz3naomLSgX2FVPZgg1j5g1RHYUdja4Sg
```

to use, just import the library (`"github.com/salrashid123/golang-jwt-pkcs11"`) configure the Yubikey wiht the pin.  Remember to set the override so that the correct `alg` is defined in the JWT header

```golang
package main

import (
	"context"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	pk "github.com/salrashid123/golang-jwt-pkcs11"
)

var ()

func main() {

	ctx := context.Background()

	var keyctx interface{}
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Issuer:    "test",
	}

	pk.SigningMethodPKRS256.Override()
	token := jwt.NewWithClaims(pk.SigningMethodPKRS256, claims)

	var slotNum = new(int)
	var err error
	// export SOFTHSM2_CONF=/path/to/softhsm.conf
	//
	// SoftHSM
	// *slotNum = 859281362 // softhsm2-util --show-slots
	// hex_id, err := hex.DecodeString("4142")
	// if err != nil {
	// 	log.Fatalf("Unable to create hex+id: %v", err)
	// }
	config := &pk.PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		KeyLabel:   "keylabel1",
    KeyId:      "rSpk6KNtMxoz3naomLSgX2FVPZgg1j5g1RHYUdja4Sg",
		//PKCS_ID:    hex_id,
		//SlotNumber: slotNum,
		Path: "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	}

	// Yubikey
	// *slotNum = 0
	// config := &pk.PKConfig{
	// 	Pin:        "123456",
	// 	TokenLabel: "YubiKey PIV #13981219",
	// 	PKCS_ID:    []byte{1},
	// 	//SlotNumber: slotNum,
	// 	Path: "/usr/local/lib/libykcs11.so.2",
	// }

	// config := &pk.PKConfig{
	// 	Pin:        "123456",
	// 	TokenLabel: "user1_esodemoapp2_com",
	// 	PKCS_ID:    []byte{1},
	// 	//SlotNumber: slotNum,
	// 	Path: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	// }

	// TPM

	// config := &pk.PKConfig{
	// 	Pin:        "mynewpin",
	// 	TokenLabel: "token1",
	// 	//SlotNumber: slotNum,
	// 	Path: "/usr/local/lib/libtpm2_pkcs11.so",
	// }

	keyctx, err = pk.NewPKContext(ctx, config)
	if err != nil {
		log.Fatalf("Unable to initialize pkcsJWT: %v", err)
	}

	if config.GetKeyID() != "" {
		token.Header["kid"] = config.GetKeyID()
	}
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}

	log.Printf("Token: %s", tokenString)

	// verify with TPM based publicKey
	keyFunc, err := pk.YKVerfiyKeyfunc(ctx, config)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with YK PublicKey")
	}

	// verify with provided RSAPublic key
	pubKey := config.GetPublicKey()

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		log.Println("     Error Parsing %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

}
```

### Setup (Yubikey)


To enable PKCS with Yubikey, you need a specific type of Yubikey that allows you to embed a certificate.  For more information for the type of keys, see:


* (YKCS11)[https://developers.yubico.com/yubico-piv-tool/YKCS11/]
* [Yubico PIV Tool](https://github.com/Yubico/yubico-piv-tool)
* [YubiKeyTokenSource](https://github.com/salrashid123/yubikey)


Once you installed `ykcs11`, specify the path to the module and either generate a key or get the key specifications.  The snippet below shows a key that was already generated earlier.


- Using `libykcs11.so.2`:

```bash
export PKCS_MODULE=/usr/local/lib/libykcs11.so.2

$  pkcs11-tool --module $PKCS_MODULE --list-token-slots
Available slots:
Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
  token label        : YubiKey PIV #13981219
  token manufacturer : Yubico (www.yubico.com)
  token model        : YubiKey YK5
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 1.0
  firmware version   : 5.27
  serial num         : 13981219
  pin min/max        : 6/48


$ pkcs11-tool --module $PKCS_MODULE  --list-objects

Certificate Object; type = X.509 cert
  label:      X.509 Certificate for PIV Authentication
  subject:    DN: C=US, O=Google, OU=Enterprise, CN=user1_esodemoapp2_com
  ID:         01
Public Key Object; RSA 2048 bits
  label:      Public key for PIV Authentication
  ID:         01
  Usage:      encrypt, verify
  Access:     local
```

- Using generic `opensc-pkcs11.so`

```bash
export PKCS_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

$ pkcs11-tool --module $PKCS_MODULE --list-token-slots
    Available slots:
    Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
      token label        : user1_esodemoapp2_com
      token manufacturer : piv_II
      token model        : PKCS#15 emulated
      token flags        : login required, rng, token initialized, PIN initialized
      hardware version   : 0.0
      firmware version   : 0.0
      serial num         : 993084513cb2a39d
      pin min/max        : 4/8


$ pkcs11-tool --module $PKCS_MODULE --slot-index=0 --list-objects
    Using slot with index 0 (0x0)
    Public Key Object; RSA 2048 bits
      label:      PIV AUTH pubkey
      ID:         01
      Usage:      encrypt, verify, wrap
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for PIV Authentication
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=user1_esodemoapp2_com
      ID:         01
    Public Key Object; RSA 2048 bits
      label:      SIGN pubkey
      ID:         02
      Usage:      encrypt, verify, wrap
      Access:     none
```

The corresponding configuration for the setting above may look like

```golang
	config := &pk.PKConfig{
		Pin:        "123456",
		TokenLabel: "YubiKey PIV #13981219",
		PKCS_ID:    []byte{1},
		Path: "/usr/local/lib/libykcs11.so.2",
	}
```


### TPM

TO use PKCS with Trusted Platform Modules, first install

[tpm2-pkcs11](https://github.com/tpm2-software/tpm2-pkcs11) as described [here](https://github.com/salrashid123/tpm2/tree/master/pkcs11#pkcs11-example-using-gcp-shielded-vm)


Then install a certificate (if you have one already configured, you would just need to bootstrap pkcs11 + tpm to reference it)

```bash
export PKCS_MODULE=/usr/local/lib/libtpm2_pkcs11.so

pkcs11-tool --module $PKCS_MODULE --slot-index=0 --list-objects
pkcs11-tool --module $PKCS_MODULE --list-token-slots
pkcs11-tool --module $PKCS_MODULE --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module $PKCS_MODULE --label="token1" --init-pin --so-pin "123456" --pin mynewpin
pkcs11-tool --module $PKCS_MODULE --list-token-slots
pkcs11-tool --module $PKCS_MODULE -l -k --key-type rsa:2048 --id 0 --label keylabel1 --pin mynewpin
pkcs11-tool --module $PKCS_MODULE --label="keylabel1" --pin mynewpin --generate-random 50 | xxd -p
pkcs11-tool --module $PKCS_MODULE --list-token-slots
pkcs11-tool --module $PKCS_MODULE --slot-index=0 --list-objects
```


```golang
	config := &pk.PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		//SlotNumber: slotNum,
		Path: "/usr/local/lib/libtpm2_pkcs11.so",
	}
```