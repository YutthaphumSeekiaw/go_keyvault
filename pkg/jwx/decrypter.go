package jwx

import (
	"context"
	"fmt"

	"go_keyvault/pkg/akv"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v3"
)

type AkvDecrypter struct {
	Client  *akv.Client
	KeyName string
	KeyID   string
}

func NewAkvDecrypter(ctx context.Context, client *akv.Client, keyName string) (*AkvDecrypter, error) {
	// We might want to fetch the key ID to verify against headers, but it's optional if we trust the flow.
	// For now, let's just store the name.
	return &AkvDecrypter{
		Client:  client,
		KeyName: keyName,
	}, nil
}

func (d *AkvDecrypter) DecryptKey(encryptedKey []byte, header jose.Header) ([]byte, error) {
	// Check if the algorithm is supported.
	// We assume RSA-OAEP or RSA-OAEP-256 based on what we use for encryption.
	var alg azkeys.JSONWebKeyEncryptionAlgorithm
	switch header.Algorithm {
	case string(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP):
		alg = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP
	case string(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256):
		alg = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
	case "RSA1_5":
		alg = azkeys.JSONWebKeyEncryptionAlgorithmRSA15
	default:
		return nil, fmt.Errorf("unsupported key encryption algorithm: %s", header.Algorithm)
	}

	// Call AKV to decrypt the key (unwrap)
	decryptedKey, err := d.Client.Decrypt(context.Background(), d.KeyName, alg, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key with AKV: %w", err)
	}

	return decryptedKey, nil
}
