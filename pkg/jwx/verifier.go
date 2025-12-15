package jwx

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"go_keyvault/pkg/akv"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v3"
)

// VerifyJWSWithAKV verifies a JWS signature using a key stored in Azure Key Vault.
// It assumes the JWS is in Compact Serialization format.
func VerifyJWSWithAKV(ctx context.Context, client *akv.Client, jwsStr string, keyName string) ([]byte, error) {
	// 1. Parse JWS to get headers and payload
	jwsObj, err := jose.ParseSigned(jwsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	if len(jwsObj.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found in JWS")
	}
	// sig := jwsObj.Signatures[0] // Not needed as we verify raw bytes

	// 2. Reconstruct the signed data (ASCII(Base64(Header)) || . || ASCII(Base64(Payload)))
	// We need the exact raw bytes of the header and payload as they appeared in the JWS string.
	// Since we have the compact string, we can split it.
	parts := strings.Split(jwsStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS compact format")
	}
	protectedHeader := parts[0]
	payload := parts[1]
	signatureB64 := parts[2]

	signedData := []byte(protectedHeader + "." + payload)

	// 3. Hash the signed data (SHA256)
	// We assume RS256 for now as per requirements.
	hasher := sha256.New()
	hasher.Write(signedData)
	digest := hasher.Sum(nil)

	// 4. Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// 5. Verify with AKV
	// Algorithm: RS256 -> RSASSA-PKCS1-v1_5 using SHA-256
	alg := azkeys.JSONWebKeySignatureAlgorithmRS256

	valid, err := client.Verify(ctx, keyName, alg, digest, signature)
	if err != nil {
		return nil, fmt.Errorf("AKV verification failed: %w", err)
	}

	if !valid {
		return nil, fmt.Errorf("signature verification failed")
	}

	// 6. Return payload (decoded)
	// The payload part of JWS compact string is Base64URL encoded.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	return payloadBytes, nil
}
