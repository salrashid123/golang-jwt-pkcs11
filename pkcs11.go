package pkcs11jwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt"

	"github.com/ThalesIgnite/crypto11"
)

type PKConfig struct {
	KeyID           string
	Path            string
	PKCS_ID         []byte
	TokenLabel      string
	KeyLabel        string
	Pin             string
	SlotNumber      *int
	publicKeyFromPK crypto.PublicKey
	crypto11Config  crypto11.Config
}

type pkConfigKey struct{}

func (k *PKConfig) GetKeyID() string {
	return k.KeyID
}

func (k *PKConfig) GetPublicKey() crypto.PublicKey {
	return k.publicKeyFromPK
}

var (
	SigningMethodPKRS128 *SigningMethodPK
	SigningMethodPKRS256 *SigningMethodPK
	errMissingConfig     = errors.New("pp: missing configuration in provided context")
	errMissingYK         = errors.New("pk: YK device not available")
)

type SigningMethodPK struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func NewPKContext(parent context.Context, val *PKConfig) (context.Context, error) {

	crypto11Config := &crypto11.Config{
		Path:       val.Path,
		TokenLabel: val.TokenLabel,
		SlotNumber: val.SlotNumber,
		Pin:        val.Pin,
	}

	cryptoctx, err := crypto11.Configure(crypto11Config)
	if err != nil {
		return nil, fmt.Errorf("pkcsjwt:  Init error loading cryptctx %v", err)
	}
	defer cryptoctx.Close()

	var priv crypto.Signer

	if val.KeyLabel == "" && len(val.PKCS_ID) > 0 {
		priv, err = cryptoctx.FindKeyPair(val.PKCS_ID, nil)
	} else if val.KeyLabel != "" && len(val.PKCS_ID) == 0 {
		priv, err = cryptoctx.FindKeyPair(nil, []byte(val.KeyLabel))
	} else {
		priv, err = cryptoctx.FindKeyPair(val.PKCS_ID, []byte(val.KeyLabel))
	}
	if priv == nil {
		return nil, fmt.Errorf("pkcsjwt:  Init could not find private key")
	}
	val.publicKeyFromPK = priv.Public()
	val.crypto11Config = *crypto11Config

	return context.WithValue(parent, pkConfigKey{}, val), nil
}

func YKFromContext(ctx context.Context) (*PKConfig, bool) {
	val, ok := ctx.Value(pkConfigKey{}).(*PKConfig)
	return val, ok
}

func init() {
	// RS256
	SigningMethodPKRS256 = &SigningMethodPK{
		"PKRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodPKRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodPKRS256
	})
}

// Alg will return the JWT header algorithm identifier this method is configured for.
func (s *SigningMethodPK) Alg() string {
	return s.alg
}

// Override will override the default JWT implementation of the signing function this Cloud KMS type implements.
func (s *SigningMethodPK) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

func (s *SigningMethodPK) Hash() crypto.Hash {
	return s.hasher
}

func (s *SigningMethodPK) Sign(signingString string, key interface{}) (string, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return "", jwt.ErrInvalidKey
	}
	config, ok := YKFromContext(ctx)
	if !ok {
		return "", errMissingConfig
	}

	cryptoctx, err := crypto11.Configure(&config.crypto11Config)
	if err != nil {
		return "", fmt.Errorf("error loading cryptctx %v", err)
	}
	defer cryptoctx.Close()

	var priv crypto.Signer

	if config.KeyLabel == "" && len(config.PKCS_ID) > 0 {
		priv, err = cryptoctx.FindKeyPair(config.PKCS_ID, nil)
	} else if config.KeyLabel != "" && len(config.PKCS_ID) == 0 {
		priv, err = cryptoctx.FindKeyPair(nil, []byte(config.KeyLabel))
	} else {
		priv, err = cryptoctx.FindKeyPair(config.PKCS_ID, []byte(config.KeyLabel))
	}
	if err != nil {
		return "", fmt.Errorf("could not init Crypto.signer %v", err)
	}

	if priv == nil {
		return "", fmt.Errorf("could not find KeyPair %v", err)
	}

	message := []byte(signingString)
	hasher := s.Hash().New()
	_, err = hasher.Write(message)
	if err != nil {
		return "", fmt.Errorf("error hashing key: %v", err)
	}

	hashed := hasher.Sum(message[:0])

	rng := rand.Reader

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("expected private key to implement crypto.Signer")
	}

	signedBytes, err := signer.Sign(rng, hashed, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf(" error from signing from YubiKey: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(signedBytes), nil
}

func YKVerfiyKeyfunc(ctx context.Context, config *PKConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.publicKeyFromPK, nil
	}, nil
}

func (s *SigningMethodPK) Verify(signingString, signature string, key interface{}) error {
	return s.override.Verify(signingString, signature, key)
}
