package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"

	"go_keyvault/pkg/akv"
	"go_keyvault/pkg/jwx"

	"github.com/go-jose/go-jose/v3"
)

func main() {
	vaultURL := os.Getenv("AZURE_KEYVAULT_URL")
	keySignName := os.Getenv("KEY_SIGN_NAME")       // KKP Private Key (Sign)
	keyDecryptName := os.Getenv("KEY_DECRYPT_NAME") // KKP Private Key (Decrypt)
	keyBotName := os.Getenv("KEY_BOT_NAME")         // BOT Public Key (in AKV)

	// Auth credentials (optional, will use DefaultAzureCredential if empty)
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

	if vaultURL == "" || keySignName == "" || keyDecryptName == "" || keyBotName == "" {
		log.Fatal("Missing environment variables: AZURE_KEYVAULT_URL, KEY_SIGN_NAME, KEY_DECRYPT_NAME, KEY_BOT_NAME")
	}

	ctx := context.Background()

	// 1. Initialize AKV Client
	fmt.Println("Initializing Azure Key Vault Client...")
	client, err := akv.NewClient(vaultURL, tenantID, clientID, clientSecret)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// --- SIMULATION SETUP ---
	// We generate a temporary RSA key to act as the "BOT" for INCOMING flow only.
	// For OUTGOING, we use the key in AKV as requested.
	fmt.Println("\n--- SIMULATION: Generating Ephemeral BOT Keys (for Incoming test) ---")
	botPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate bot key: %v", err)
	}
	// botPubKey := &botPrivKey.PublicKey // Not used in V2 AKV flow

	// --- OUTGOING FLOW ---
	// Member Bank (Us) -> BOT
	fmt.Println("\n=== OUTGOING FLOW (Member Bank -> BOT) ===")
	plaintextOut := "Payment Instruction 12345"
	fmt.Printf("1. Plaintext: %s\n", plaintextOut)

	// Use AKV Key for Encryption
	jweOut, err := Outgoing(ctx, client, plaintextOut, keySignName, keyBotName)
	if err != nil {
		log.Fatalf("Outgoing failed: %v", err)
	}
	fmt.Printf("5. JWE (Sent to BOT): %s\n", jweOut)

	// --- INCOMING FLOW ---
	// BOT -> Member Bank (Us)
	fmt.Println("\n=== INCOMING FLOW (BOT -> Member Bank) ===")

	// First, we must SIMULATE the BOT creating a message for us.
	// BOT signs with BOT Private Key.
	// BOT encrypts with KKP Public Key (which we must fetch to simulate).
	fmt.Println("(Simulating BOT creating message...)")

	// Fetch KKP Public Key (for Encryption) from AKV
	kkpDecryptKeyJWK, err := client.GetKey(ctx, keyDecryptName)
	if err != nil {
		log.Fatalf("Failed to get KKP decrypt key: %v", err)
	}
	// Convert JWK to RSA Public Key
	kkpPubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(kkpDecryptKeyJWK.N),
		E: int(new(big.Int).SetBytes(kkpDecryptKeyJWK.E).Int64()),
	}

	plaintextIn := "Payment Status: SUCCESS"
	jweIn, err := SimulateBotMessage(plaintextIn, botPrivKey, kkpPubKey)
	if err != nil {
		log.Fatalf("Simulation failed: %v", err)
	}
	fmt.Printf("Received JWE from BOT: %s\n", jweIn)

	// Now, run the actual Incoming logic
	decryptedText, err := Incoming(ctx, client, jweIn, keyDecryptName, keyBotName)
	if err != nil {
		log.Fatalf("Incoming failed: %v", err)
	}
	fmt.Printf("Final Decrypted Text: %s\n", decryptedText)
}

// Outgoing implements the Member Bank -> BOT flow
func Outgoing(ctx context.Context, client *akv.Client, plaintext string, signKeyName string, encryptKeyName string) (string, error) {
	// 1. EncodeBase64
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	fmt.Printf("2. Base64 Encoded: %s\n", encoded)

	// 2. Sign Base64 with KKP Private Key (JWS)
	signer, err := jwx.NewAkvSigner(ctx, client, signKeyName)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}
	jwsStr, err := jwx.Sign([]byte(encoded), signer)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	fmt.Printf("3. JWS: %s\n", jwsStr)

	// 3. Encrypt JWS with BOT Public Key (JWE) using AKV Encrypt
	encrypter, err := jwx.NewAkvKeyEncrypter(ctx, client, encryptKeyName)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Create OpaqueEncrypter
	// Use A256GCM as requested
	// Set cty: JWT
	opts := new(jose.EncrypterOptions)
	opts.WithType("JWT")
	opts.WithContentType("JWT") // cty header

	joseEncrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: encrypter}, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create jose encrypter: %w", err)
	}

	jweObj, err := joseEncrypter.Encrypt([]byte(jwsStr))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	jweCompact, err := jweObj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	// Convert to Custom JSON
	jweJSON, err := jwx.CompactToCustomJSON(jweCompact)
	if err != nil {
		return "", fmt.Errorf("failed to convert to custom JSON: %w", err)
	}

	fmt.Printf("4. Encrypted JWE to Custom JSON (via AKV)\n")

	return jweJSON, nil
}

// Incoming implements the BOT -> Member Bank flow
func Incoming(ctx context.Context, client *akv.Client, jweJSON string, decryptKeyName string, verifyKeyName string) (string, error) {
	// 0. Convert Custom JSON to Compact
	jweCompact, err := jwx.CustomJSONToCompact(jweJSON)
	if err != nil {
		return "", fmt.Errorf("failed to convert custom JSON to compact: %w", err)
	}

	// 1. Decrypt JWE with KKP Private Key
	decrypter, err := jwx.NewAkvDecrypter(ctx, client, decryptKeyName)
	if err != nil {
		return "", fmt.Errorf("failed to create decrypter: %w", err)
	}
	jwsBytes, err := jwx.DecryptJWE(jweCompact, decrypter)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt JWE: %w", err)
	}
	jwsStr := string(jwsBytes)
	fmt.Printf("1. Decrypted JWE to JWS: %s\n", jwsStr)

	// 2. Verify JWS Base64 with BOT Public Key (via AKV)
	payloadBytes, err := jwx.VerifyJWSWithAKV(ctx, client, jwsStr, verifyKeyName)
	if err != nil {
		return "", fmt.Errorf("failed to verify JWS: %w", err)
	}
	encoded := string(payloadBytes)
	fmt.Printf("2. Verified JWS Payload (Base64): %s\n", encoded)

	// 3. DecodeBase64
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	return string(decodedBytes), nil
}

// SimulateBotMessage creates a message as if it were the BOT
func SimulateBotMessage(plaintext string, botPrivKey *rsa.PrivateKey, kkpPubKey *rsa.PublicKey) (string, error) {
	// 1. EncodeBase64
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))

	// 2. Sign with BOT Private Key
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: botPrivKey}, nil)
	if err != nil {
		return "", err
	}
	jwsObj, err := signer.Sign([]byte(encoded))
	if err != nil {
		return "", err
	}
	jwsStr, err := jwsObj.CompactSerialize()
	if err != nil {
		return "", err
	}

	// 3. Encrypt with KKP Public Key
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: kkpPubKey}, nil)
	if err != nil {
		return "", err
	}
	jweObj, err := encrypter.Encrypt([]byte(jwsStr))
	if err != nil {
		return "", err
	}

	return jweObj.CompactSerialize()
}

func DecryptWithSecret(ctx context.Context, client *akv.Client, jweStr string, secretName string) ([]byte, error) {
	// 1. Fetch the Private Key from AKV Secret
	// This downloads the actual key material to your app
	privateKeyPEM, err := client.GetSecret(ctx, secretName)
	if err != nil {
		return nil, err
	}

	// 2. Parse the Private Key (assuming it's stored as PEM)
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	// Parse PKCS1 or PKCS8 depending on your key format
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// 3. Parse the JWE
	jweObj, err := jose.ParseEncrypted(jweStr)
	if err != nil {
		return nil, err
	}

	decryptedPayload, err := jweObj.Decrypt(privateKey)
	if err != nil {
		return nil, err
	}

	return decryptedPayload, nil
}

func EncryptWithSecret(ctx context.Context, client *akv.Client, plaintext []byte, secretName string) (string, error) {
	// 1. Fetch the Public Key from AKV Secret
	pubKeyPEM, err := client.GetSecret(ctx, secretName)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	// 2. Parse PEM
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	// 3. Parse RSA Public Key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try PKCS1 if PKIX fails
		if pk, err2 := x509.ParsePKCS1PublicKey(block.Bytes); err2 == nil {
			pubKey = pk
		} else {
			return "", fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	// 4. Encrypt LOCALLY
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: pubKey}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	jweObj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	return jweObj.CompactSerialize()
}
