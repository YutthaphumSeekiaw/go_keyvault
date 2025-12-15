package jwx

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"go_keyvault/pkg/akv"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v3"
)

type AkvSigner struct {
	Client  *akv.Client
	KeyName string
	KeyID   string
	PubKey  *rsa.PublicKey
}

func NewAkvSigner(ctx context.Context, client *akv.Client, keyName string) (*AkvSigner, error) {
	// Fetch the key to get the Key ID and Public Key
	akvKey, err := client.GetKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	if *akvKey.Kty != azkeys.JSONWebKeyTypeRSA && *akvKey.Kty != azkeys.JSONWebKeyTypeRSAHSM {
		return nil, fmt.Errorf("unsupported key type: %s", *akvKey.Kty)
	}

	// Convert AKV JWK to rsa.PublicKey
	// akvKey.N and akvKey.E are already []byte (raw bytes)
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(akvKey.N),
		E: int(new(big.Int).SetBytes(akvKey.E).Int64()),
	}

	var kid string
	if akvKey.KID != nil {
		kid = string(*akvKey.KID)
	}

	return &AkvSigner{
		Client:  client,
		KeyName: keyName,
		KeyID:   kid,
		PubKey:  pubKey,
	}, nil
}

// Public returns the public key of the signer.
func (s *AkvSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       s.PubKey,
		KeyID:     s.KeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

// Algs returns the supported algorithms.
func (s *AkvSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// SignPayload signs the payload using Azure Key Vault.
func (s *AkvSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.RS256 {
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	hashed := sha256.Sum256(payload)

	// RS256 in AKV
	sig, err := s.Client.Sign(context.Background(), s.KeyName, azkeys.JSONWebKeySignatureAlgorithmRS256, hashed[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}
