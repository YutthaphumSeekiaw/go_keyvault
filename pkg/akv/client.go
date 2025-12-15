package akv

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

type Client struct {
	KeysClient    *azkeys.Client
	SecretsClient *azsecrets.Client
}

func NewClient(vaultURL, tenantID, clientID, clientSecret string) (*Client, error) {
	var cred azcore.TokenCredential
	var err error

	if tenantID != "" && clientID != "" && clientSecret != "" {
		cred, err = azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	} else {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	keysClient, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create keys client: %w", err)
	}

	secretsClient, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets client: %w", err)
	}

	return &Client{
		KeysClient:    keysClient,
		SecretsClient: secretsClient,
	}, nil
}

func (c *Client) GetSecret(ctx context.Context, name string) (string, error) {
	resp, err := c.SecretsClient.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", name, err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("secret %s has no value", name)
	}
	return *resp.Value, nil
}

func (c *Client) Sign(ctx context.Context, keyName string, alg azkeys.JSONWebKeySignatureAlgorithm, digest []byte) ([]byte, error) {
	resp, err := c.KeysClient.Sign(ctx, keyName, "", azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with key %s: %w", keyName, err)
	}
	return resp.Result, nil
}

func (c *Client) Verify(ctx context.Context, keyName string, alg azkeys.JSONWebKeySignatureAlgorithm, digest []byte, signature []byte) (bool, error) {
	resp, err := c.KeysClient.Verify(ctx, keyName, "", azkeys.VerifyParameters{
		Algorithm: &alg,
		Digest:    digest,
		Signature: signature,
	}, nil)
	if err != nil {
		return false, fmt.Errorf("failed to verify with key %s: %w", keyName, err)
	}
	return *resp.Value, nil
}

func (c *Client) Decrypt(ctx context.Context, keyName string, alg azkeys.JSONWebKeyEncryptionAlgorithm, ciphertext []byte) ([]byte, error) {
	resp, err := c.KeysClient.Decrypt(ctx, keyName, "", azkeys.KeyOperationsParameters{
		Algorithm: &alg,
		Value:     ciphertext,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with key %s: %w", keyName, err)
	}
	return resp.Result, nil
}

func (c *Client) Encrypt(ctx context.Context, keyName string, alg azkeys.JSONWebKeyEncryptionAlgorithm, plaintext []byte) ([]byte, error) {
	resp, err := c.KeysClient.Encrypt(ctx, keyName, "", azkeys.KeyOperationsParameters{
		Algorithm: &alg,
		Value:     plaintext,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with key %s: %w", keyName, err)
	}
	return resp.Result, nil
}

func (c *Client) GetKey(ctx context.Context, keyName string) (*azkeys.JSONWebKey, error) {
	resp, err := c.KeysClient.GetKey(ctx, keyName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s: %w", keyName, err)
	}
	return resp.Key, nil
}
