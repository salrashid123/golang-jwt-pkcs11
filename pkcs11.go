package pkcs11jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"encoding/asn1"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/ThalesGroup/crypto11"
)

type PKConfig struct {
	KeyID           string
	Path            string
	PKCS_ID         []byte
	TokenLabel      string
	TokenSerial     string
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
	SigningMethodPKRS256 *SigningMethodPK
	SigningMethodPKPS256 *SigningMethodPK
	SigningMethodPKES256 *SigningMethodPK
	errMissingConfig     = errors.New("pp: missing configuration in provided context")
)

type SigningMethodPK struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func NewPKContext(parent context.Context, val *PKConfig) (context.Context, error) {

	crypto11Config := &crypto11.Config{
		Path: val.Path,
		Pin:  val.Pin,
	}

	valset := 0
	if val.TokenLabel != "" {
		crypto11Config.TokenLabel = val.TokenLabel
		valset++
	}
	if val.SlotNumber != nil {
		crypto11Config.SlotNumber = val.SlotNumber
		valset++
	}

	if val.TokenSerial != "" {
		crypto11Config.TokenSerial = val.TokenSerial
		valset++
	}

	if valset != 1 {
		return nil, fmt.Errorf("pkcsjwt: exactly one of tokenlabel or slotnumber or tokenserial must be specified")
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

	// PS256
	SigningMethodPKPS256 = &SigningMethodPK{
		"PKPS256",
		jwt.SigningMethodPS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodPKPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodPKPS256
	})

	// ES256
	SigningMethodPKES256 = &SigningMethodPK{
		"PKES256",
		jwt.SigningMethodES256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodPKES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodPKES256
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

func (s *SigningMethodPK) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}
	config, ok := YKFromContext(ctx)
	if !ok {
		return nil, errMissingConfig
	}

	cryptoctx, err := crypto11.Configure(&config.crypto11Config)
	if err != nil {
		return nil, fmt.Errorf("error loading cryptctx %v", err)
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
		return nil, fmt.Errorf("could not init Crypto.signer %v", err)
	}

	if priv == nil {
		return nil, fmt.Errorf("could not find KeyPair %v", err)
	}

	message := []byte(signingString)
	hasher := s.Hash().New()
	_, err = hasher.Write(message)
	if err != nil {
		return nil, fmt.Errorf("error hashing key: %v", err)
	}

	hashed := hasher.Sum(message[:0])

	rng := rand.Reader

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("expected private key to implement crypto.Signer")
	}

	var signedBytes []byte
	if s.Alg() == "PS256" {
		sopts := &rsa.PSSOptions{
			Hash:       s.Hash(),
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
		signedBytes, err = signer.Sign(rng, hashed, sopts)
		if err != nil {
			return nil, fmt.Errorf(" error from signing from PKCS11 PSS: %v", err)
		}

	} else {
		signedBytes, err = signer.Sign(rng, hashed, s.Hash())
		if err != nil {
			return nil, fmt.Errorf(" error from signing from PKCS11: %v", err)
		}

	}

	if s.alg == "ES256" {
		epub := priv.Public().(*ecdsa.PublicKey)
		curveBits := epub.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}
		out := make([]byte, 2*keyBytes)

		var esig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signedBytes, &esig); err != nil {
			return nil, err
		}

		esig.R.FillBytes(out[0:keyBytes])
		esig.S.FillBytes(out[keyBytes:])
		return out, nil
	}

	return signedBytes, nil
}

func YKVerfiyKeyfunc(ctx context.Context, config *PKConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.publicKeyFromPK, nil
	}, nil
}

func (s *SigningMethodPK) Verify(signingString string, signature []byte, key interface{}) error {
	return s.override.Verify(signingString, []byte(signature), key)
}
