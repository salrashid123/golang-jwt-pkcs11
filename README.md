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

* `RS256`
* `PS256`
* `ES256`

(i just didn't'' have the time to account for the additional types)

### Setup (softHSM)

First [install softHSM](https://github.com/opendnssec/SoftHSMv2).

You can either use the pregenerated data here in the `test_data/` folder or create a key and generate a JWT

To use the pregenerated softhsm config, edit `softhsm.conf` and set the absolute path of `directories.tokendir = /path/to/golang-jwt-pkcs11/test_data`, then set

```bash
export SOFTHSM2_CONF=/path/to/golang-jwt-pkcs11/test_data/softhsm.conf 
```

To generate a new keyset from scratch:

```bash
sudo apt-get install libsofthsm2-dev opensc
mkdir -p $HOME/soft_hsm/tokens

## edit softhsm.conf and set the absolute value of path
$ cat /path/to/test_data/softhsm.conf 
log.level = DEBUG
objectstore.backend = file
directories.tokendir = /path/to/soft_hsm/tokens
slots.removable = true

export SOFTHSM2_CONF=/path/to/golang-jwt-pkcs11/softhsm.conf

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-mechanisms --slot-index 0

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots

    Available slots:
    Slot 0 (0x5a08e6cf): SoftHSM slot ID 0x5a08e6cf
      token label        : token1
      token manufacturer : SoftHSM project
      token model        : SoftHSM v2
      token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
      hardware version   : 2.6
      firmware version   : 2.6
      serial num         : c7ce2755da08e6cf
      pin min/max        : 4/255
    Slot 1 (0x1): SoftHSM slot ID 0x1
      token state:   uninitialized



$ softhsm2-util --show-slots

    Available slots:
    Slot 1510532815
        Slot info:
            Description:      SoftHSM slot ID 0x5a08e6cf                                      
            Manufacturer ID:  SoftHSM project                 
            Hardware version: 2.6
            Firmware version: 2.6
            Token present:    yes
        Token info:
            Manufacturer ID:  SoftHSM project                 
            Model:            SoftHSM v2      
            Hardware version: 2.6
            Firmware version: 2.6
            Serial number:    c7ce2755da08e6cf
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
    Using slot 0 with a present token (0x5a08e6cf)
    Key pair generated:
    Private Key Object; RSA
      label:      keylabel1
      ID:         4142
      Usage:      decrypt, sign, signRecover, unwrap
      Access:     sensitive, always sensitive, never extractable, local
    Public Key Object; RSA 2048 bits
      label:      keylabel1
      ID:         4142
      Usage:      encrypt, verify, verifyRecover, wrap
      Access:     local

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type ec:prime256v1 --id 4143 --label keylabel2 --pin mynewpin

    Using slot 0 with a present token (0x5a08e6cf)
    Key pair generated:
    Private Key Object; EC
      label:      keylabel2
      ID:         4143
      Usage:      decrypt, sign, signRecover, unwrap, derive
      Access:     sensitive, always sensitive, never extractable, local
    Public Key Object; EC  EC_POINT 256 bits
      EC_POINT:   0441041c83a886c449b9a0ee75d39d6e68f46b6fde30b29c029194073b7089d795eac7b2c76c536f108e99931c5e8abf64ba21da3dd123406805b077e7bab942129cce
      EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
      label:      keylabel2
      ID:         4143
      Usage:      encrypt, verify, verifyRecover, wrap, derive
      Access:     local

```

then to run,

```bash
$ export SOFTHSM2_CONF=/full/path/to/golang-jwt-pkcs11/test_data/softhsm.conf 
$ cd examples/
$ go run main.go 

2024/05/05 14:23:29 -------------- RS256 --------------
2024/05/05 14:23:29      PublicKey: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6Nf7IY7aFlF05+PrP98
I9W8Pghj8iaE47DIAlwFZwtz65X7K0Q+jSndQ807NCejeQoCBjfxJVzU1e0oF6Pi
zeTRPd9lyDFZPHhBeMKt59zFcks4qGRGHSm2s+gclW5bjPzTIyVVcsR6qq7MKEmr
stDpkvTCUzJgAIJvMVRKq4NmERcaoH9LZFoU2tl9J15i93Vd2ldU27XFPxuzL53E
ASwmb/3ykiMhzSOWcfXmkTelUabVPG1BRtLnvB+1Ke9UM4xxviU+H9k3NyhJmLME
xF/IyjtF8Uo9tO4kVJi9Gwri1cWvWCl9imEfbyEsnvOYySKjxwsfrWyZeioPtnAL
vwIDAQAB
-----END PUBLIC KEY-----
2024/05/05 14:23:29 Token: eyJhbGciOiJSUzI1NiIsImtpZCI6IlBtSjd6SmZjemJ2UWVlVS9rZEZ0anhnZHJXcVNtK1NiY3VGcmZhN0E3dTg9IiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE0OTMzNDY5fQ.qfrX9dApibMueZQZOzcnc_DKNeszM_soKfPO1e_-fwpa8eTH2pBHkpHsowcSrWN7Ci9pb9EPDtkMIxE5qC6y1Szn_xwdIwSCkto-YUvAUCP2m6SLgBu4XRPvDHkCrCux7QVJql93ndstskmI8Vf8fJ4cAMzDwRDIoChxeiCkOK49uqhCIx5nhB8Ezmq4ud6x2QIBkO3uv2HWMM00AZBHBoo6AQVVBGVE05fW99gvCiZxwE0mMsi1rgFKFo4bpKVlVMFPYmL_i07dUk4Y4EIjkiJb-PrFkRAwystr2AaAdvPxOHAWJlp0K_7FZC1yuPMmAf78elqEJLnWJ_7wr_T25A
2024/05/05 14:23:29      verified with PublicKey
2024/05/05 14:23:29      verified with exported PubicKey


2024/05/05 14:23:29 -------------- ES256 --------------
2024/05/05 14:23:29      PublicKey: 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHIOohsRJuaDuddOdbmj0a2/eMLKc
ApGUBztwideV6seyx2xTbxCOmZMcXoq/ZLoh2j3RI0BoBbB357q5QhKczg==
-----END PUBLIC KEY-----
2024/05/05 14:23:29 Token: eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1IiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzE0OTMzNDY5fQ.MA8h5rB5Sl_tv5yaOWJoeHj6OKX2nBJfCjuc2DgPLmGyQ7vzqUFRPshXrTEjCjtdNTagKAkq3-geo3iKIhFJSA
2024/05/05 14:23:29      verified with PublicKey
2024/05/05 14:23:29      verified with exported PubicKey
```

The JWT is formatted as:

```json
{
  "alg": "RS256",
  "kid": "PmJ7zJfczbvQeeU/kdFtjxgdrWqSm+SbcuFrfa7A7u8=",
  "typ": "JWT"
}
{
  "iss": "test",
  "exp": 1714933469
}
```

Where the `keyID` is the base64 encoded hash of the DER public key as shown below (it can be anything you want)

```bash
$ openssl rsa -pubin -in rsapublic.pem -outform DER | openssl sha256
writing RSA key
SHA256(stdin)= 3e627bcc97dccdbbd079e53f91d16d8f181dad6a929be49b72e16b7daec0eeef

# base64 of hex 3e627bcc97dccdbbd079e53f91d16d8f181dad6a929be49b72e16b7daec0eeef --> PmJ7zJfczbvQeeU/kdFtjxgdrWqSm+SbcuFrfa7A7u8=
```

to use, just import the library (`"github.com/salrashid123/golang-jwt-pkcs11"`) configure the Yubikey with the pin.  Remember to set the override so that the correct `alg` is defined in the JWT header

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
		KeyId:      "PmJ7zJfczbvQeeU/kdFtjxgdrWqSm+SbcuFrfa7A7u8=",
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