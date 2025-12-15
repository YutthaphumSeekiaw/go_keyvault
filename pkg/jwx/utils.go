package jwx

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go_keyvault/pkg/akv"

	"github.com/go-jose/go-jose/v3"
)

// GetPublicKeyFromSecret fetches a PEM encoded public key from AKV Secret
func GetPublicKeyFromSecret(ctx context.Context, client *akv.Client, secretName string) (*rsa.PublicKey, error) {
	secretValue, err := client.GetSecret(ctx, secretName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(secretValue))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try PKCS1
		if pub, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not of type RSA")
	}

	return rsaPub, nil
}

// Encrypt creates a JWE using the given public key.
func Encrypt(payload []byte, pubKey *rsa.PublicKey) (string, error) {
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: pubKey},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	obj, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	return obj.CompactSerialize()
}

// DecryptJWE decrypts a JWE string using the AKV Decrypter.
func DecryptJWE(jweStr string, decrypter *AkvDecrypter) ([]byte, error) {
	obj, err := jose.ParseEncrypted(jweStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	plaintext, err := obj.Decrypt(decrypter)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE: %w", err)
	}

	return plaintext, nil
}

// VerifyJWS verifies a JWS string using the given public key.
func VerifyJWS(jwsStr string, pubKey *rsa.PublicKey) ([]byte, error) {
	obj, err := jose.ParseSigned(jwsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	output, err := obj.Verify(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %w", err)
	}

	return output, nil
}

// Sign creates a JWS using the AKV Signer.
func Sign(payload []byte, signer *AkvSigner) (string, error) {
	// Create a jose.Signer that uses our OpaqueSigner
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signer},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	obj, err := joseSigner.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return obj.CompactSerialize()
}
