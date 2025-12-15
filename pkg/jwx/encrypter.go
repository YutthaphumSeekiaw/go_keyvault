package jwx

import (
	"context"
	"fmt"

	"go_keyvault/pkg/akv"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v3"
)

type AkvKeyEncrypter struct {
	Client  *akv.Client
	KeyName string
	kid     string
}

func NewAkvKeyEncrypter(ctx context.Context, client *akv.Client, keyName string) (*AkvKeyEncrypter, error) {
	// Fetch key to get ID (optional, but good for headers)
	akvKey, err := client.GetKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	var kid string
	if akvKey.KID != nil {
		kid = string(*akvKey.KID)
	}

	return &AkvKeyEncrypter{
		Client:  client,
		KeyName: keyName,
		kid:     kid,
	}, nil
}

func (e *AkvKeyEncrypter) KeyID() string {
	return e.kid
}

func (e *AkvKeyEncrypter) Algs() []jose.KeyAlgorithm {
	return []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.RSA_OAEP}
}

func (e *AkvKeyEncrypter) EncryptKey(cek []byte, alg jose.KeyAlgorithm) (jose.Recipient, error) {
	var akvAlg azkeys.JSONWebKeyEncryptionAlgorithm
	switch alg {
	case jose.RSA_OAEP_256:
		akvAlg = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
	case jose.RSA_OAEP:
		akvAlg = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP
	default:
		return jose.Recipient{}, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	encryptedKey, err := e.Client.Encrypt(context.Background(), e.KeyName, akvAlg, cek)
	if err != nil {
		return jose.Recipient{}, err
	}

	// Store the encrypted key in the 'Key' field.
	// go-jose will use this to populate the JWE's encrypted_key field.
	return jose.Recipient{
		Algorithm: alg,
		KeyID:     e.kid,
		Key:       encryptedKey,
	}, nil
}
