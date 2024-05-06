package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	pk "github.com/salrashid123/golang-jwt-pkcs11"
)

var ()

func main() {

	ctx := context.Background()

	log.Println("-------------- RS256 --------------")

	var keyctx interface{}
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	pk.SigningMethodPKRS256.Override()
	token := jwt.NewWithClaims(pk.SigningMethodPKRS256, claims)

	var slotNum = new(int)
	var err error
	// export SOFTHSM2_CONF=/path/to/golang-jwt-pkcs11/test_data/softhsm.conf
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
		KeyID:      "PmJ7zJfczbvQeeU/kdFtjxgdrWqSm+SbcuFrfa7A7u8=",
		//PKCS_ID:    hex_id,
		//SlotNumber: slotNum,
		Path: "/usr/lib/softhsm/libsofthsm2.so",
	}

	// Yubikey
	*slotNum = 0
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

	ap := config.GetPublicKey()
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		log.Fatalf("Unable to convert ekpub: %v", err)
	}

	rakPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	log.Printf("     PublicKey: \n%v", string(rakPubPEM))

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
		log.Println("     verified with PublicKey")
	}

	// verify with provided RSAPublic key
	pubKey := config.GetPublicKey()

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		log.Printf("     Error Parsing %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

	// ****************************************************************

	log.Println("-------------- ES256 --------------")
	// ES256

	pk.SigningMethodPKES256.Override()
	estoken := jwt.NewWithClaims(pk.SigningMethodPKES256, claims)

	esconfig := &pk.PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		KeyLabel:   "keylabel2",
		KeyID:      "12345",
		//PKCS_ID:    hex_id,
		//SlotNumber: slotNum,
		Path: "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	}

	eskeyctx, err := pk.NewPKContext(ctx, esconfig)
	if err != nil {
		log.Fatalf("Unable to initialize pkcsJWT: %v", err)
	}

	esap := esconfig.GetPublicKey()
	esakBytes, err := x509.MarshalPKIXPublicKey(esap)
	if err != nil {
		log.Fatalf("Unable to convert ekpub: %v", err)
	}

	esPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: esakBytes,
		},
	)
	log.Printf("     PublicKey: \n%v", string(esPubPEM))

	if esconfig.GetKeyID() != "" {
		estoken.Header["kid"] = esconfig.GetKeyID()
	}

	estokenString, err := estoken.SignedString(eskeyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}

	log.Printf("Token: %s", estokenString)

	// verify with TPM based publicKey
	eskeyFunc, err := pk.YKVerfiyKeyfunc(ctx, esconfig)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	esvtoken, err := jwt.Parse(estokenString, eskeyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if esvtoken.Valid {
		log.Println("     verified with PublicKey")
	}

	// verify with provided RSAPublic key
	eepubKey := esconfig.GetPublicKey()

	ev, err := jwt.Parse(estokenString, func(token *jwt.Token) (interface{}, error) {
		return eepubKey, nil
	})
	if err != nil {
		log.Printf("     Error Parsing %v", err)
	}
	if ev.Valid {
		log.Println("     verified with exported PubicKey")
	}

	// ****************************************************************

}
