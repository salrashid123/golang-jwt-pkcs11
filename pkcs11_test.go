package pkcs11jwt

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	pin      = "mynewpin"
	confPath = "./test_data/softhsm.conf"
)

/*
$ export SOFTHSM2_CONF=softhsm.conf
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

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

*/

var (
	//lib = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	lib = "/usr/lib/softhsm/libsofthsm2.so"
)

func TestPKCSPublic(t *testing.T) {

	t.Setenv("SOFTHSM2_CONF", confPath)

	ctx := context.Background()

	SigningMethodPKRS256.Override()
	config := &PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		KeyLabel:   "keylabel1",
		KeyID:      "4142",
		Path:       lib,
	}

	_, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	ap := config.GetPublicKey()

	pubKey, ok := ap.(*rsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, 2048, pubKey.Size()*8)
}

func TestPKCSRSA(t *testing.T) {

	t.Setenv("SOFTHSM2_CONF", confPath)

	ctx := context.Background()

	SigningMethodPKRS256.Override()
	config := &PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		KeyLabel:   "keylabel1",
		KeyID:      "PmJ7zJfczbvQeeU/kdFtjxgdrWqSm+SbcuFrfa7A7u8=",
		Path:       lib,
	}

	_, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodPKRS256, claims)

	keyctx, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := YKVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestTPMClaim(t *testing.T) {
	t.Setenv("SOFTHSM2_CONF", confPath)

	ctx := context.Background()

	SigningMethodPKRS256.Override()
	config := &PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		KeyLabel:   "keylabel1",
		KeyID:      "PmJ7zJfczbvQeeU/kdFtjxgdrWqSm+SbcuFrfa7A7u8=",
		Path:       lib,
	}

	_, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodPKRS256, claims)

	keyctx, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := YKVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	tokenIssuer, err := vtoken.Claims.GetIssuer()
	require.NoError(t, err)
	require.Equal(t, issuer, tokenIssuer)
}

func TestPKCSECC(t *testing.T) {
	t.Setenv("SOFTHSM2_CONF", confPath)
	ctx := context.Background()

	SigningMethodPKES256.Override()
	config := &PKConfig{
		Pin:        "mynewpin",
		TokenLabel: "token1",
		KeyLabel:   "keylabel2",
		Path:       lib,
	}

	_, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodPKES256, claims)

	keyctx, err := NewPKContext(ctx, config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := YKVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
