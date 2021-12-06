// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"flag"

	"log"

	"github.com/ThalesIgnite/crypto11"
	"github.com/lestrrat-go/jwx/jwk"
)

const ()

var ()

var ()

func main() {

	flag.Parse()
	log.Printf("======= Init  ========")

	// **** SOFTHSM

	// export SOFTHSM2_CONF=/home/srashid/Desktop/misc/soft_hsm/softhsm.conf
	//
	// SoftHSM
	// //*slotNum = 859281362 // softhsm2-util --show-slots
	hex_id, err := hex.DecodeString("4142")
	if err != nil {
		log.Fatalf("Unable to create hex+id: %v", err)
	}
	pin := "mynewpin"
	tokenLabel := "token1"
	label := "keylabel1"
	pkcs_id := hex_id
	path := "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

	// **** Yubikey
	// pin := "123456"
	// tokenLabel := "YubiKey PIV #13981219"
	// label := ""
	// pkcs_id := []byte{1}
	// // 	//SlotNumber: slotNum,
	// path := "/usr/local/lib/libykcs11.so.2"

	// pin := "123456"
	// tokenLabel := "user1_esodemoapp2_com"
	// label := ""
	// pkcs_id := []byte{1}
	// // 	//SlotNumber: slotNum,
	// path := "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

	// **** TPM
	// pin := "mynewpin"
	// tokenLabel := "token1"
	// //SlotNumber: slotNum,
	// path := "/usr/local/lib/libtpm2_pkcs11.so"

	// label := ""
	// pkcs_id := []byte{0}

	crypto11Config := &crypto11.Config{
		Path:       path,
		TokenLabel: tokenLabel,
		Pin:        pin,
	}

	cryptoctx, err := crypto11.Configure(crypto11Config)
	if err != nil {
		log.Fatalf("pkcsjwt:  Init error loading cryptctx %v", err)
	}
	defer cryptoctx.Close()

	var priv crypto.Signer

	if label == "" && len(pkcs_id) > 0 {
		priv, err = cryptoctx.FindKeyPair(pkcs_id, nil)
	} else if tokenLabel != "" && len(pkcs_id) == 0 {
		priv, err = cryptoctx.FindKeyPair(nil, []byte(tokenLabel))
	} else {
		priv, err = cryptoctx.FindKeyPair(pkcs_id, []byte(label))
	}
	if priv == nil {
		log.Fatalf("pkcsjwt:  Init could not find private key")
	}
	kPublicKey := priv.Public()

	var kid string
	rkey, ok := priv.Public().(*rsa.PublicKey)
	if ok {
		plaintext := []byte(rkey.N.String())
		h := sha256.New()
		_, err = h.Write(plaintext)
		if err != nil {
			log.Fatalf("%v", err)
		}
		plaintextHash := h.Sum([]byte{})
		kid = hex.EncodeToString(plaintextHash)
	}

	rsaKey, ok := priv.Public().(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Could not convert key to rsa key")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(rsaKey)
	if err != nil {
		log.Fatalf("Error decoing public key %v", err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	log.Printf("     PublicKey: \n%v", string(pubBytes))

	jkey, err := jwk.New(kPublicKey)
	if err != nil {
		log.Fatalf("failed to create symmetric key: %s\n", err)
	}

	jkey.Set(jwk.KeyIDKey, kid)

	buf, err := json.MarshalIndent(jkey, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal key into JSON: %s\n", err)
		return
	}
	fmt.Printf("JWK Format:\n%s\n", buf)

}
